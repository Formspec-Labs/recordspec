// Shared harness lives in `stack_common_postgres::testing`; this file only
// adds the pool step every test here starts from.

use sqlx::PgPool;
use stack_common_postgres::testing::EphemeralCluster;
use trellis_store_postgres_async::build_pool;

/// Gate F: prove the server rejects cleartext, then connect over TLS.
pub async fn tls_pool(cluster: &EphemeralCluster, max_connections: u32) -> PgPool {
    cluster.assert_tls_contract().await;
    build_pool(&cluster.dsn(), max_connections).await.unwrap()
}
