"""Prepare an inactive exact-case grant successor from pinned native Start evidence.

This program has no installation, HTTP, process, credential, or database operation.
Root must separately review the resulting bytes and authorize atomic replacement.
"""
import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from jsonschema import Draft202012Validator

HERE = Path(__file__).resolve().parent
PRIVATE = Path('/Users/mikewolfd/Library/Application Support/Formspec Stack/local-demos/trellis-full-d1-20261009-v1')
PROFILE = PRIVATE / 'oidc-profile-source-native-v8.json'
GRANTS = PRIVATE / 'current-grants-source-native-v8.json'
PROFILE_SHA = '55589b8ee357064b9eb648411253d5cacb27b559e2e8017fe4593f8ccc3492bf'
GRANTS_SHA = 'ec5b8c592da9bc620d41b7c3c85836c8c4fa071f8045585539e19be9ae531cd9'
LIMIT = 1048576


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'non-finite JSON value'))


def read(path, private=False):
    path = Path(path)
    require(path.is_absolute(), 'absolute input path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid(), 'owned regular input required')
        if private:
            require(info.st_mode & 0o077 == 0, 'private input permissions differ')
        raw = stream.read(LIMIT + 1)
        require(len(raw) <= LIMIT, 'input exceeds 1 MiB')
        return raw


def pointer(document, location):
    require(location == '' or location.startswith('/'), 'invalid JSON pointer')
    require(re.search(r'~(?![01])', location) is None, 'invalid JSON pointer escape')
    for token in location.split('/')[1:] if location else []:
        token = token.replace('~1', '/').replace('~0', '~')
        if isinstance(document, list):
            require(re.fullmatch(r'0|[1-9][0-9]*', token) is not None, 'invalid array pointer')
            document = document[int(token)]
        else:
            document = document[token]
    return document


def evidence(ref):
    raw = read(ref['path'])
    require(sha(raw) == ref['sha256'], 'evidence hash differs')
    return pointer(decode(raw), ref['pointer'])


def nonempty(value):
    require(isinstance(value, str) and bool(value.strip()), 'nonempty evidenced string required')
    return value


def validate(schema, document):
    Draft202012Validator(schema).validate(document)


def validate_committed_start(ref, start):
    """Validate the owning readback and exact persisted receipt, without claiming HTTP capture."""
    require(ref['pointer'] == '', 'complete reservation readback receipt required')
    receipt = evidence(ref)
    require(receipt['status'] == 'ACTUAL_STARTED_CASE_SOURCE_OWNER_BINDING_READBACK_PASS',
            'verified owning reservation readback required')
    rows_raw = read(Path(ref['path']).parent / 'rows.private.jsonl', True)
    require(sha(rows_raw) == receipt['privateRowsSha256'], 'reservation rows hash differs')
    rows = [decode(line) for line in rows_raw.splitlines() if line.strip()]
    outcomes = [row for row in rows if 'outcome_bytes' in row]
    require(len(outcomes) == 1, 'one persisted Start outcome required')
    row = outcomes[0]
    encoded = row['outcome_bytes']
    require(isinstance(encoded, str) and encoded.startswith('\\x'), 'persisted bytea outcome required')
    require(decode(bytes.fromhex(encoded[2:])) == start, 'persisted Start outcome differs')
    require(start['caseLedgerId'] == 'urn:wos:' + receipt['caseId']
            and row['case_id'] == receipt['caseId']
            and start['caseReference'] == receipt['caseReference'] == row['case_reference']
            and start['draftRef'] == receipt['draftRef'] == row['draft_ref']
            and row['source_id'] == receipt['sourceBinding']['sourceId']
            and row['source_binding'] == receipt['sourceBinding'],
            'committed case, draft or source binding differs')


def prepare(selection):
    validate(decode((HERE / 'selection.schema.json').read_bytes()), selection)
    profile_raw, baseline_raw = read(PROFILE, True), read(GRANTS, True)
    require(sha(profile_raw) == PROFILE_SHA and sha(baseline_raw) == GRANTS_SHA, 'active baseline changed; reselect and review')
    profile, baseline = decode(profile_raw), decode(baseline_raw)
    require(profile['grantsFile'] == GRANTS.name and profile['tenantScope'] == baseline['tenantScope'], 'active grants selection differs')
    require(any(row['principal'] == 'wos-trellis-producer' and row['clientId'] == 'formspec-wos-trellis-dev'
                and row['subject'] == '4af85e55-7498-43e7-ab7b-c5c08aa05b4f'
                and row['issuer'] == 'http://127.0.0.1:18090/realms/formspec-dev'
                for row in profile['identities']), 'existing WOS mapping differs')
    require(not any(row['principal'] == 'wos-trellis-producer' for row in baseline['grants']), 'existing WOS grants require new review')
    for selected in selection['qualifiedCallerInputs']:
        require(sha(read(selected['path'])) == selected['sha256'], 'qualified caller input differs')
    start = evidence(selection['startResponse'])
    require(isinstance(start, dict) and set(start) == {'caseLedgerId', 'caseReference', 'draftRef', 'status'},
            'closed native ApplicationCaseReceipt required')
    require(start['draftRef'] == selection['expectedDraftRef'] and start['status'] == 'in-progress',
            'new selected draft reservation required')
    if 'committedReservation' in selection:
        validate_committed_start(selection['committedReservation'], start)
    else:
        start_status = evidence(selection['startStatus'])
        require(type(start_status) is int and start_status == 200,
                'retained successful Start HTTP status required')
    wire = nonempty(start['caseLedgerId'])
    nonempty(start['caseReference'])
    require(wire.startswith('urn:wos:'), 'native Start case URN required')
    scope = wire[len('urn:wos:'):]
    require(scope.isascii() and scope.strip() == scope and '/' not in scope and '_case_' in scope,
            'native raw case scope differs')
    actors = [{'kind': row['kind'], 'subject': nonempty(evidence(row['subject']))} for row in selection['actors']]
    require(len({(row['kind'], row['subject']) for row in actors}) == len(actors), 'duplicate append actor')
    selectors = []
    for row in selection['payloadActors']:
        pointer({}, row['pointer']) if row['pointer'] == '' else require(
            row['pointer'].startswith('/') and re.search(r'~(?![01])', row['pointer']) is None, 'invalid selector')
        subjects = [nonempty(evidence(ref)) for ref in row['subjects']]
        require(len(set(subjects)) == len(subjects), 'duplicate selector subject')
        selectors.append({'pointer': row['pointer'], 'required': row['required'], 'subjects': subjects})
    require(len({row['pointer'] for row in selectors}) == len(selectors), 'duplicate selector pointer')
    additions = [{'principal': 'wos-trellis-producer', 'scope': scope, 'action': 'read'},
                 {'principal': 'wos-trellis-producer', 'scope': scope, 'action': 'append',
                  'actors': actors, 'payloadActors': selectors}]
    successor = {'tenantScope': baseline['tenantScope'], 'grants': baseline['grants'] + additions}
    validate(decode((HERE / 'grants.schema.json').read_bytes()), successor)
    require(successor['grants'][:len(baseline['grants'])] == baseline['grants'], 'existing authority changed')
    return successor, scope


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', required=True)
    parser.add_argument('--output-directory', required=True)
    args = parser.parse_args()
    selected_raw = read(args.selection)
    selected = decode(selected_raw)
    successor, scope = prepare(selected)
    out = Path(args.output_directory)
    require(out.is_absolute() and out.parent == PRIVATE and out.name.startswith('wos-case-grant-prepared-'),
            'inactive private output location required')
    out.mkdir(mode=0o700)  # Existing directory refuses a repeated preparation.
    raw = (json.dumps(successor, indent=2) + '\n').encode()
    require(len(raw) <= LIMIT, 'grant successor exceeds maintained file cap')
    with os.fdopen(os.open(out / 'candidate-grants.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        stream.write(raw)
    receipt = {'status': 'inactive schema-validated exact-case candidate; not installed',
               'selectionSha256': sha(selected_raw), 'candidateSha256': sha(raw), 'caseScope': scope,
               'target': str(GRANTS), 'expectedTargetSha256': GRANTS_SHA,
               'profileSha256': PROFILE_SHA, 'restartRequired': False,
               'sourceGrantsPreserved': True, 'addedActions': ['read', 'append'],
               'administerAdded': False, 'liveOperationsPerformed': False}
    with os.fdopen(os.open(out / 'preparation-receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        json.dump(receipt, stream, indent=2); stream.write('\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
