//! Durable bundle publication helpers.

use sqlx::PgPool;

/// Stored bundle identity reserved before artifact publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundlePublicationIdentity {
    pub scope: Vec<u8>,
    pub checkpoint_digest: String,
    pub seal_version: u64,
    pub export_attempt_id: String,
}

/// Stored bundle record after artifact publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundlePublicationRecord {
    pub identity: BundlePublicationIdentity,
    pub artifact_ref: String,
}

/// Error returned when bundle publication persistence fails.
#[derive(Debug, thiserror::Error)]
pub enum BundlePublicationError {
    /// Numeric identity field does not fit the Postgres schema.
    #[error("bundle seal_version {0} does not fit Postgres BIGINT")]
    DomainViolation(u64),
    /// A durable row already binds this seal or checkpoint to a different identity.
    #[error("bundle publication conflict: {0}")]
    Conflict(&'static str),
    /// SQL execution failed.
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Reserves a bundle identity before artifact bytes are written.
///
/// This makes `(scope, seal_version)` and `(scope, checkpoint_digest)` conflicts
/// durable across Trellis server processes. Repeating the same identity is
/// idempotent.
///
/// # Errors
/// Returns [`BundlePublicationError::Conflict`] when either durable key already
/// points at a different export attempt.
pub async fn reserve_bundle_publication(
    pool: &PgPool,
    identity: &BundlePublicationIdentity,
) -> Result<(), BundlePublicationError> {
    let seal_version = seal_version_i64(identity.seal_version)?;
    sqlx::query(
        "\
INSERT INTO trellis_bundle_publications (
    scope, seal_version, checkpoint_digest, export_attempt_id
) VALUES ($1, $2, $3, $4)
ON CONFLICT DO NOTHING",
    )
    .bind(&identity.scope)
    .bind(seal_version)
    .bind(&identity.checkpoint_digest)
    .bind(&identity.export_attempt_id)
    .execute(pool)
    .await?;

    ensure_publishable(pool, identity).await
}

/// Records the artifact reference for a previously reserved bundle identity.
///
/// Repeating the same record is idempotent. Reusing the identity with a
/// different artifact reference is rejected.
///
/// # Errors
/// Returns [`BundlePublicationError::Conflict`] when durable identity or
/// artifact-reference bindings disagree.
pub async fn publish_bundle_publication(
    pool: &PgPool,
    record: &BundlePublicationRecord,
) -> Result<(), BundlePublicationError> {
    reserve_bundle_publication(pool, &record.identity).await?;
    let seal_version = seal_version_i64(record.identity.seal_version)?;
    let rows = sqlx::query(
        "\
UPDATE trellis_bundle_publications
SET artifact_ref = $5,
    published_at = COALESCE(published_at, now())
WHERE scope = $1
  AND seal_version = $2
  AND checkpoint_digest = $3
  AND export_attempt_id = $4
  AND (artifact_ref IS NULL OR artifact_ref = $5)",
    )
    .bind(&record.identity.scope)
    .bind(seal_version)
    .bind(&record.identity.checkpoint_digest)
    .bind(&record.identity.export_attempt_id)
    .bind(&record.artifact_ref)
    .execute(pool)
    .await?
    .rows_affected();
    if rows == 1 {
        Ok(())
    } else {
        Err(BundlePublicationError::Conflict(
            "bundle identity already has a different artifact ref",
        ))
    }
}

/// Looks up a published bundle by checkpoint digest.
///
/// Reserved-but-unpublished rows are intentionally hidden.
///
/// # Errors
/// Returns [`BundlePublicationError::Sqlx`] for query failures.
pub async fn get_bundle_publication_by_digest(
    pool: &PgPool,
    scope: &[u8],
    checkpoint_digest: &str,
) -> Result<Option<BundlePublicationRecord>, BundlePublicationError> {
    let row: Option<(Vec<u8>, i64, String, String, String)> = sqlx::query_as(
        "\
SELECT scope, seal_version, checkpoint_digest, export_attempt_id, artifact_ref
FROM trellis_bundle_publications
WHERE scope = $1
  AND checkpoint_digest = $2
  AND artifact_ref IS NOT NULL",
    )
    .bind(scope)
    .bind(checkpoint_digest)
    .fetch_optional(pool)
    .await?;

    row.map(
        |(scope, seal_version, checkpoint_digest, export_attempt_id, artifact_ref)| {
            Ok(BundlePublicationRecord {
                identity: BundlePublicationIdentity {
                    scope,
                    checkpoint_digest,
                    seal_version: u64::try_from(seal_version).map_err(|_| {
                        BundlePublicationError::Conflict("stored seal_version is negative")
                    })?,
                    export_attempt_id,
                },
                artifact_ref,
            })
        },
    )
    .transpose()
}

async fn ensure_publishable(
    pool: &PgPool,
    identity: &BundlePublicationIdentity,
) -> Result<(), BundlePublicationError> {
    let seal_version = seal_version_i64(identity.seal_version)?;
    if let Some(existing) = identity_by_seal(pool, &identity.scope, seal_version).await?
        && existing != *identity
    {
        return Err(BundlePublicationError::Conflict(
            "seal version already has a different bundle identity",
        ));
    }
    if let Some(existing) =
        identity_by_digest(pool, &identity.scope, &identity.checkpoint_digest).await?
        && existing != *identity
    {
        return Err(BundlePublicationError::Conflict(
            "checkpoint digest already has a different bundle identity",
        ));
    }
    Ok(())
}

/// Returns only a published bundle at the exact scope and seal.
///
/// Reuses immutable identity and digest lookup; reservations remain hidden.
///
/// # Errors
/// Refuses an out-of-range seal, SQL failure, or inconsistent persisted identity.
pub async fn get_bundle_publication_by_seal(
    pool: &PgPool,
    scope: &[u8],
    seal: u64,
) -> Result<Option<BundlePublicationRecord>, BundlePublicationError> {
    let sql_seal =
        i64::try_from(seal).map_err(|_| BundlePublicationError::DomainViolation(seal))?;
    let Some(identity) = identity_by_seal(pool, scope, sql_seal).await? else {
        return Ok(None);
    };
    let record = get_bundle_publication_by_digest(pool, scope, &identity.checkpoint_digest).await?;
    if let Some(record) = &record {
        if record.identity != identity || identity.scope != scope || identity.seal_version != seal {
            return Err(BundlePublicationError::Conflict(
                "published seal identity mismatch",
            ));
        }
    }
    Ok(record)
}

async fn identity_by_seal(
    pool: &PgPool,
    scope: &[u8],
    seal_version: i64,
) -> Result<Option<BundlePublicationIdentity>, BundlePublicationError> {
    let row: Option<(Vec<u8>, i64, String, String)> = sqlx::query_as(
        "\
SELECT scope, seal_version, checkpoint_digest, export_attempt_id
FROM trellis_bundle_publications
WHERE scope = $1 AND seal_version = $2",
    )
    .bind(scope)
    .bind(seal_version)
    .fetch_optional(pool)
    .await?;
    row.map(identity_from_row).transpose()
}

async fn identity_by_digest(
    pool: &PgPool,
    scope: &[u8],
    checkpoint_digest: &str,
) -> Result<Option<BundlePublicationIdentity>, BundlePublicationError> {
    let row: Option<(Vec<u8>, i64, String, String)> = sqlx::query_as(
        "\
SELECT scope, seal_version, checkpoint_digest, export_attempt_id
FROM trellis_bundle_publications
WHERE scope = $1 AND checkpoint_digest = $2",
    )
    .bind(scope)
    .bind(checkpoint_digest)
    .fetch_optional(pool)
    .await?;
    row.map(identity_from_row).transpose()
}

fn identity_from_row(
    (scope, seal_version, checkpoint_digest, export_attempt_id): (Vec<u8>, i64, String, String),
) -> Result<BundlePublicationIdentity, BundlePublicationError> {
    Ok(BundlePublicationIdentity {
        scope,
        checkpoint_digest,
        seal_version: u64::try_from(seal_version)
            .map_err(|_| BundlePublicationError::Conflict("stored seal_version is negative"))?,
        export_attempt_id,
    })
}

fn seal_version_i64(seal_version: u64) -> Result<i64, BundlePublicationError> {
    i64::try_from(seal_version).map_err(|_| BundlePublicationError::DomainViolation(seal_version))
}
