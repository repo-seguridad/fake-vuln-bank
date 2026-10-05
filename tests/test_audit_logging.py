"""
Tests for the Logs / Auditoria module (audit_log.py).

Every test here is a specification of a *deliberate* vulnerability. They exist to
pin the current (insecure) behavior, which serves two purposes:

1. Phase 1/2 evidence: a reviewer can run the suite and watch each finding execute.
2. Phase 3: these tests are inverted into the "no-reincidencia" proof, because a
   PoC that still passes after remediation means the fix did not hold.

The fake stores follow the repository convention from test_merchant_payments.py and
test_runtime_smoke.py: psycopg2 is stubbed out, the connection pool is neutralized
while `app` imports, and execute_query is replaced per module. The audit store also
captures every statement it receives, so the SQL injection tests can assert on the
SQL that actually reached the driver instead of on the rows that came back.
"""

import importlib
import os
import sys
import types
import unittest
from datetime import datetime
from unittest.mock import patch


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

AUDIT_COLUMN_KEYS = (
    'id', 'event_type', 'severity', 'actor_id', 'actor_username', 'action',
    'target', 'details', 'ip_address', 'user_agent', 'referer', 'request_id',
    'http_method', 'endpoint', 'result', 'signature', 'created_at',
)

USER_COLUMN_KEYS = (
    'id', 'username', 'password', 'account_number', 'balance', 'is_admin',
    'profile_picture', 'reset_pin', 'bio', 'is_suspended',
    'username_xss_detected_at', 'bio_xss_detected_at',
)


def install_fake_psycopg2():
    if 'psycopg2' in sys.modules:
        return

    fake_psycopg2 = types.ModuleType('psycopg2')
    fake_pool_module = types.ModuleType('psycopg2.pool')
    fake_pool_module.PoolError = Exception
    fake_pool_module.SimpleConnectionPool = object
    fake_pool_module.ThreadedConnectionPool = object
    fake_psycopg2.pool = fake_pool_module

    sys.modules['psycopg2'] = fake_psycopg2
    sys.modules['psycopg2.pool'] = fake_pool_module


def split_sql_values(block):
    """Split a VALUES block on top-level commas, respecting single-quoted strings."""

    cells = []
    current = []
    inside_string = False
    index = 0

    while index < len(block):
        character = block[index]

        if inside_string:
            if character == "'":
                if block[index + 1:index + 2] == "'":
                    current.append("''")
                    index += 2
                    continue
                inside_string = False
            current.append(character)
        elif character == "'":
            inside_string = True
            current.append(character)
        elif character == ',':
            cells.append(''.join(current))
            current = []
        else:
            current.append(character)

        index += 1

    cells.append(''.join(current))
    return [cell.strip() for cell in cells]


class FakeAuditStore:
    """In-memory audit_log that records the raw SQL every statement carried."""

    def __init__(self):
        self.created_at = datetime(2026, 10, 5, 9, 14, 22)
        self.rows = []
        self.statements = []
        self.raw_statements = []
        self.next_id = 1

    # -- fixtures --------------------------------------------------------

    def add_entry(self, **overrides):
        entry = {
            'id': self.next_id,
            'event_type': 'LOGIN_SUCCESS',
            'severity': 'INFO',
            'actor_id': 1,
            'actor_username': 'admin',
            'action': 'login',
            'target': 'admin',
            'details': 'account_number=ADMIN001',
            'ip_address': '127.0.0.1',
            'user_agent': 'curl/8.4.0',
            'referer': None,
            'request_id': None,
            'http_method': 'POST',
            'endpoint': '/login',
            'result': 'SUCCESS',
            'signature': None,
            'created_at': self.created_at,
        }
        entry.update(overrides)
        entry['id'] = self.next_id
        self.rows.append(entry)
        self.next_id += 1
        return entry

    def find(self, row_id):
        for entry in self.rows:
            if entry["id"] == row_id:
                return entry
        return None

    def find_matching(self, fragment):
        return [
            entry for entry in self.rows
            if fragment in str(entry.get('event_type') or '')
        ]

    def tuple_for(self, entry):
        return tuple(entry[column] for column in AUDIT_COLUMN_KEYS)

    # -- the patched execute_query ---------------------------------------

    def execute_query(self, query, params=None, fetch=True):
        raw = query
        normalized = ' '.join(query.split())
        upper = normalized.upper()

        self.raw_statements.append(raw)
        self.statements.append(normalized)

        if 'INSERT INTO AUDIT_LOG' in upper:
            entry = self._insert_from_statement(raw)
            return [self.tuple_for(entry)] if entry else []

        if 'UPDATE AUDIT_LOG SET' in upper:
            return self._update(normalized, upper)

        if 'DELETE FROM AUDIT_LOG' in upper:
            return self._delete(normalized, upper)

        if 'FROM AUDIT_LOG' in upper:
            return self._select(normalized, upper)

        return []

    def _insert_from_statement(self, raw):
        marker = 'VALUES ('
        start = raw.upper().find(marker)
        if start == -1:
            return None

        block = raw[start + len(marker):raw.rfind(')')]
        cells = split_sql_values(block)
        if len(cells) < 15:
            return None

        def text(index):
            value = cells[index]
            if value.upper() == 'NULL':
                return None
            if value.startswith("'") and value.endswith("'"):
                value = value[1:-1]
            return value or None

        return self.add_entry(
            event_type=text(0),
            severity=text(1),
            actor_id=text(2),
            actor_username=text(3),
            action=text(4),
            target=text(5),
            details=text(6),
            ip_address=text(7),
            user_agent=text(8),
            referer=text(9),
            request_id=text(10),
            http_method=text(11),
            endpoint=text(12),
            result=text(13),
            created_at=text(14),
        )

    def _update(self, normalized, upper):
        entry = self.find(self._single_int(normalized))
        if entry is None:
            return []

        where_position = upper.find(' WHERE ')
        if where_position == -1:
            where_position = len(upper)

        for column in AUDIT_COLUMN_KEYS:
            marker = f'SET {column.upper()} = '
            position = upper.find(marker)
            if position == -1:
                continue
            value = normalized[position + len(marker):where_position].strip()
            if value.startswith("'") and value.endswith("'"):
                value = value[1:-1]
            entry[column] = value

        return []

    def _delete(self, normalized, upper):
        if ' WHERE ' not in upper:
            removed = list(self.rows)
            self.rows = []
            return [self.tuple_for(entry) for entry in removed]

        entry = self.find(self._single_int(normalized))
        if entry is None:
            return []

        self.rows.remove(entry)
        return [self.tuple_for(entry)]

    def _select(self, normalized, upper):
        if 'GROUP BY SEVERITY' in upper:
            return self._group('severity')

        if 'GROUP BY EVENT_TYPE' in upper:
            return self._group('event_type')

        if 'GROUP BY ACTOR_USERNAME' in upper:
            return self._group('actor_username')

        if 'DATE_TRUNC' in upper:
            return [(self.created_at, len(self.rows))]

        if 'COUNT(*)' in upper and 'SIGNATURE' in upper:
            return [(len([e for e in self.rows if not e["signature"]]),)]

        if 'COUNT(*)' in upper:
            if ' WHERE ' in upper:
                return [(len(self._rows_for_where(normalized)),)]
            return [(len(self.rows),)]

        if ' WHERE ID =' in upper:
            entry = self.find(self._single_int(normalized))
            return [self.tuple_for(entry)] if entry else []

        if ' WHERE ' in upper:
            return [self.tuple_for(entry) for entry in self._rows_for_where(normalized)]

        return [self.tuple_for(entry) for entry in self.rows]

    def _group(self, column):
        counts = {}
        for entry in self.rows:
            counts[entry[column]] = counts.get(entry[column], 0) + 1
        return [(key, value) for key, value in sorted(counts.items(), key=lambda kv: -kv[1])]

    def _single_int(self, normalized):
        tail = normalized.rsplit('WHERE', 1)[-1]
        digits = ''
        for character in tail:
            if character.isdigit():
                digits += character
            elif digits:
                break
        return int(digits) if digits else -1

    def _rows_for_where(self, normalized):
        where = normalized[normalized.upper().rfind('WHERE') + len('WHERE'):]
        where = where.split(' ORDER BY ', 1)[0]
        where = where.split(' LIMIT ', 1)[0]
        return [entry for entry in self.rows if self._matches(entry, where)]

    def _matches(self, entry, where):
        clause = where.split(' OR ', 1)[0]
        column = None
        expected = None

        for name in AUDIT_COLUMN_KEYS:
            for marker in (f'{name.upper()} = ', f'{name.upper()} ILIKE '):
                if marker in clause.upper():
                    column = name
                    expected = clause.split(marker, 1)[1].strip()
                    break
            if column:
                break

        if column is None:
            return True

        if expected.upper() == 'NULL':
            return entry.get(column) is None

        actual = '' if entry.get(column) is None else str(entry.get(column))
        return expected.strip("'").strip('%').lower() in actual.lower()

    # -- assertions helpers ---------------------------------------------

    def trail_selects(self):
        return [
            statement for statement in self.statements
            if statement.startswith('SELECT') and 'FROM audit_log' in statement
        ]

    def deletes(self):
        return [
            statement for statement in self.statements
            if statement.startswith('DELETE FROM audit_log')
        ]

    def any_statement(self):
        return '\n'.join(self.statements)


class FakeUserStore:
    """Enough of the users table for the login, register and bio flows."""

    def __init__(self):
        self.created_at = datetime(2026, 10, 5, 9, 14, 22)
        self.users = {
            'admin': {
                'id': 1,
                'username': 'admin',
                'password': 'admin123',
                'account_number': 'ADMIN001',
                'balance': 1000000.0,
                'is_admin': True,
                'profile_picture': None,
                'reset_pin': None,
                'bio': '',
                'is_suspended': False,
                'username_xss_detected_at': None,
                'bio_xss_detected_at': None,
                'created_at': self.created_at,
            },
            'mallory': {
                'id': 7,
                'username': 'mallory',
                'password': 'mallory123',
                'account_number': 'MALL001',
                'balance': 250.0,
                'is_admin': False,
                'profile_picture': None,
                'reset_pin': None,
                'bio': '',
                'is_suspended': False,
                'username_xss_detected_at': None,
                'bio_xss_detected_at': None,
                'created_at': self.created_at,
            },
        }
        self.next_id = 8
        self.statements = []

    def tuple_for(self, user):
        return tuple(user[column] for column in USER_COLUMN_KEYS)

    def execute_query(self, query, params=None, fetch=True):
        normalized = ' '.join(query.split())
        upper = normalized.upper()
        self.statements.append(normalized)

        if 'SELECT * FROM USERS WHERE USERNAME=' in upper:
            username = normalized.split("username='", 1)[1].split("'", 1)[0]
            password = normalized.split("password='", 1)[1].split("'", 1)[0]
            user = self.users.get(username)
            if user and user['password'] == password:
                return [self.tuple_for(user)]
            return []

        if upper.startswith('SELECT USERNAME FROM USERS'):
            username = params[0] if params else None
            return [(username,)] if username in self.users else []

        if 'SELECT ACCOUNT_NUMBER, BALANCE FROM USERS' in upper:
            user_id = params[0] if params else None
            for user in self.users.values():
                if user['id'] == user_id:
                    return [(user['account_number'], user['balance'])]
            return []

        if 'INSERT INTO USERS' in upper:
            self.next_id += 1
            start = upper.index('(', upper.index('INSERT INTO USERS'))
            end = upper.index(')', start)
            columns = [column.strip().lower() for column in upper[start + 1:end].split(',')]
            supplied = dict(zip(columns, params or []))

            username = supplied.get('username')
            if not username:
                return []

            user = {
                'id': self.next_id,
                'username': username,
                'password': supplied.get('password'),
                'account_number': supplied.get('account_number') or 'ACC900001',
                'balance': 1000.0,
                'is_admin': bool(supplied.get('is_admin')),
                'profile_picture': None,
                'reset_pin': None,
                'bio': supplied.get('bio') or '',
                'is_suspended': False,
                'username_xss_detected_at': None,
                'bio_xss_detected_at': None,
                'created_at': self.created_at,
            }
            self.users[username] = user
            return [(user['id'], user['username'], user['account_number'], user['balance'], user['is_admin'])]

        if 'UPDATE USERS SET BIO' in upper:
            bio = params[0] if params else ''
            user_id = params[1] if params and len(params) > 1 else None
            for user in self.users.values():
                if user['id'] == user_id:
                    user['bio'] = bio
            return []

        return []

    def suspend(self, username):
        self.users[username]['is_suspended'] = True


class AuditLoggingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_fake_psycopg2()

        import database

        cls._original_init_connection_pool = database.init_connection_pool
        database.init_connection_pool = lambda *args, **kwargs: None

        if 'app' in sys.modules:
            del sys.modules['app']

        try:
            cls.app_module = importlib.import_module('app')
        except ModuleNotFoundError as exc:
            raise unittest.SkipTest(
                f'App dependencies are not installed locally: {exc.name}'
            ) from exc
        finally:
            database.init_connection_pool = cls._original_init_connection_pool

        cls.audit_module = importlib.import_module('audit_log')
        cls.client = cls.app_module.app.test_client()

        from auth import generate_token

        cls.customer_token = generate_token(7, 'mallory', False)
        cls.admin_token = generate_token(1, 'admin', True)

    def setUp(self):
        self.store = FakeAuditStore()
        self.users = FakeUserStore()

        patches = [
            patch.object(self.audit_module, 'execute_query', side_effect=self.store.execute_query),
            patch.object(self.app_module, 'execute_query', side_effect=self.users.execute_query),
            patch.object(self.app_module, 'execute_transaction', side_effect=self._noop_transaction),
        ]
        for audit_patch in patches:
            audit_patch.start()
            self.addCleanup(audit_patch.stop)

    def _noop_transaction(self, queries):
        return None

    def _auth(self, token=None):
        return {'Authorization': f'Bearer {token or self.customer_token}'}

    # ------------------------------------------------------------------
    # AV-01 · SQL injection in the console filters
    # ------------------------------------------------------------------

    def test_search_filter_is_interpolated_into_the_statement(self):
        response = self.client.get(
            "/api/audit/logs?search=' OR '1'='1",
            headers=self._auth(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("OR '1'='1", self.store.any_statement())

    def test_union_select_reaches_the_users_table(self):
        response = self.client.get(
            "/api/audit/logs?search=' UNION SELECT username, password, balance FROM users--",
            headers=self._auth(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            'UNION SELECT username, password, balance FROM users',
            self.store.any_statement(),
        )

    def test_event_type_filter_is_interpolated(self):
        response = self.client.get(
            "/api/audit/logs?event_type=LOGIN_SUCCESS' OR '1'='1",
            headers=self._auth(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("event_type = 'LOGIN_SUCCESS' OR '1'='1'", self.store.any_statement())

    def test_severity_filter_is_interpolated(self):
        response = self.client.get(
            "/api/audit/logs?severity=INFO' OR '1'='1",
            headers=self._auth(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("severity = 'INFO' OR '1'='1'", self.store.any_statement())

    def test_actor_filter_is_interpolated(self):
        response = self.client.get(
            "/api/audit/logs?actor=admin%' OR '1'='1",
            headers=self._auth(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("actor_username ILIKE '%admin%' OR '1'='1%'", self.store.any_statement())

    def test_date_filters_are_interpolated(self):
        response = self.client.get(
            "/api/audit/logs?from=2026-01-01' OR '1'='1",
            headers=self._auth(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("created_at >= '2026-01-01' OR '1'='1'", self.store.any_statement())

    def test_order_by_is_interpolated(self):
        response = self.client.get(
            '/api/audit/logs?order=created_at, (SELECT password FROM users LIMIT 1)',
            headers=self._auth(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('(SELECT password FROM users LIMIT 1)', self.store.any_statement())

    def test_limit_and_offset_are_interpolated(self):
        response = self.client.get(
            '/api/audit/logs?limit=1; DELETE FROM audit_log;--',
            headers=self._auth(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('LIMIT 1; DELETE FROM audit_log;--', self.store.any_statement())

    def test_stats_window_is_interpolated(self):
        response = self.client.get('/api/audit/stats?window=24', headers=self._auth())

        self.assertEqual(response.status_code, 200)
        self.assertIn('make_interval(hours => 24)', self.store.any_statement())

    def test_stats_severity_filter_is_interpolated(self):
        response = self.client.get(
            "/api/audit/stats?severity=INFO' OR '1'='1",
            headers=self._auth(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("severity = 'INFO' OR '1'='1'", self.store.any_statement())

    def test_purge_cutoff_is_interpolated(self):
        response = self.client.post(
            '/admin/audit/purge',
            headers=self._auth(),
            json={'before': "2026-01-01 00:00:00' OR '1'='1"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("created_at < '2026-01-01 00:00:00' OR '1'='1'", self.store.any_statement())

    def test_edit_values_are_interpolated(self):
        entry = self.store.add_entry()

        response = self.client.post(
            f'/admin/audit/logs/{entry["id"]}',
            headers=self._auth(),
            json={'details': "x' WHERE '1'='1"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("SET details = 'x' WHERE '1'='1'", self.store.any_statement())

    def test_integrity_sweep_limit_is_interpolated(self):
        response = self.client.get(
            '/admin/audit/integrity-check?limit=500; DELETE FROM audit_log;--',
            headers=self._auth(self.admin_token),
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('LIMIT 500; DELETE FROM audit_log;--', self.store.any_statement())

    def test_tail_line_count_is_interpolated(self):
        response = self.client.get(
            '/api/audit/tail?lines=50; DELETE FROM audit_log;--',
            headers=self._auth(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('LIMIT 50; DELETE FROM audit_log;--', self.store.any_statement())

    # ------------------------------------------------------------------
    # AV-02 · IDOR
    # ------------------------------------------------------------------

    def test_any_authenticated_user_reads_the_admin_trail_entry(self):
        admin_entry = self.store.add_entry(actor_username='admin')

        response = self.client.get(
            f'/api/audit/logs/{admin_entry["id"]}',
            headers=self._auth(self.customer_token),
        )

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body['entry']['actor_username'], 'admin')
        self.assertFalse(body['debug_info']['requested_by_is_admin'])

    def test_any_authenticated_user_filters_by_another_actor_id(self):
        response = self.client.get(
            '/api/audit/logs?user_id=1',
            headers=self._auth(self.customer_token),
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('actor_id = 1', self.store.any_statement())

    def test_tail_leaks_the_whole_trail_to_any_token(self):
        self.store.add_entry(actor_username='admin')

        response = self.client.get('/api/audit/tail?lines=10', headers=self._auth())

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body['debug_info']['requested_by'], 'mallory')
        self.assertTrue(any('actor=admin' in line for line in body['lines']))

    def test_stats_leaks_the_whole_trail_to_any_token(self):
        self.store.add_entry(actor_username='admin')

        response = self.client.get('/api/audit/stats', headers=self._auth(self.customer_token))

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body['stats']['top_actors'][0]['actor_username'], 'admin')

    def test_export_leaks_the_whole_trail_to_any_token(self):
        self.store.add_entry(actor_username='admin')

        response = self.client.get(
            '/api/audit/logs/export?format=json',
            headers=self._auth(self.customer_token),
        )

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body['entries'][0]['actor_username'], 'admin')

    # ------------------------------------------------------------------
    # AV-03 · Missing function level authorization
    # ------------------------------------------------------------------

    def test_non_admin_edits_an_audit_entry(self):
        entry = self.store.add_entry(event_type='LOGIN_FAILED', actor_username='admin')

        response = self.client.post(
            f'/admin/audit/logs/{entry["id"]}',
            headers=self._auth(self.customer_token),
            json={'event_type': 'INFO', 'actor_username': 'admin'},
        )

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body['status'], 'success')
        self.assertFalse(body['debug_info']['edited_by_is_admin'])
        self.assertEqual(entry['event_type'], 'INFO')
        self.assertEqual(entry['actor_username'], 'admin')

    def test_non_admin_deletes_an_audit_entry(self):
        entry = self.store.add_entry(event_type='LOGIN_FAILED')

        response = self.client.delete(
            f'/api/audit/logs/{entry["id"]}',
            headers=self._auth(self.customer_token),
        )

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body['status'], 'success')
        self.assertFalse(body['debug_info']['deleted_by_is_admin'])
        self.assertIsNone(self.store.find(entry['id']))

    def test_non_admin_purges_the_entire_trail(self):
        self.store.add_entry(event_type='LOGIN_SUCCESS')
        self.store.add_entry(event_type='LOGIN_FAILED')

        response = self.client.post(
            '/admin/audit/purge',
            headers=self._auth(self.customer_token),
            json={'all': True},
        )

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body['scope'], 'all')
        self.assertFalse(body['debug_info']['purged_by_is_admin'])
        self.assertEqual(self.store.rows, [])

    def test_edit_is_never_re_verified_afterwards(self):
        entry = self.store.add_entry()

        response = self.client.post(
            f'/admin/audit/logs/{entry["id"]}',
            headers=self._auth(),
            json={'details': 'rewritten'},
        )

        self.assertFalse(response.get_json()['debug_info']['integrity_rechecked'])

    def test_delete_returns_the_whole_removed_entry(self):
        entry = self.store.add_entry(event_type='LOGIN_FAILED', details='account suspended')

        response = self.client.delete(
            f'/api/audit/logs/{entry["id"]}',
            headers=self._auth(),
        )

        deleted = response.get_json()['deleted']
        self.assertEqual(deleted['event_type'], 'LOGIN_FAILED')
        self.assertEqual(deleted['details'], 'account suspended')
        self.assertEqual(deleted['severity'], 'INFO')

    # ------------------------------------------------------------------
    # AV-04 · Path traversal in the export
    # ------------------------------------------------------------------

    def test_export_filename_traversal_reads_a_file_outside_the_export_directory(self):
        probe_path = os.path.join(REPO_ROOT, 'poc_lfi_probe.txt')
        with open(probe_path, 'w', encoding='utf-8') as handle:
            handle.write('DB_PASSWORD=postgres\n')

        try:
            response = self.client.get(
                '/api/audit/logs/export?filename=../../poc_lfi_probe.txt',
                headers=self._auth(),
            )

            self.assertEqual(response.status_code, 200)
            self.assertIn(b'DB_PASSWORD=postgres', response.data)
        finally:
            os.remove(probe_path)

    def test_export_filename_traversal_reads_application_source(self):
        response = self.client.get(
            '/api/audit/logs/export?filename=../../app.py',
            headers=self._auth(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Flask(__name__)', response.data)

    def test_export_returns_the_whole_trail_in_one_request(self):
        for _ in range(5):
            self.store.add_entry()

        response = self.client.get(
            '/api/audit/logs/export?format=json',
            headers=self._auth(),
        )

        body = response.get_json()
        self.assertEqual(body['count'], 5)
        self.assertIn('LIMIT 5000', self.store.any_statement())

    def test_export_format_is_not_whitelisted(self):
        response = self.client.get(
            '/api/audit/logs/export?format=php',
            headers=self._auth(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data.startswith(b'id,event_type'))

    # ------------------------------------------------------------------
    # AV-05 / AV-06 / AV-07 · XSS sinks and missing CSP
    # ------------------------------------------------------------------

    def test_note_is_stored_verbatim_with_a_forged_actor(self):
        payload = '<img src=x onerror=alert(document.cookie)>'

        response = self.client.post(
            '/api/audit/note',
            headers=self._auth(self.customer_token),
            json={
                'details': payload,
                'actor_username': 'admin',
                'event_type': 'LOGIN_SUCCESS',
                'severity': 'INFO',
            },
        )

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body['entry']['details'], payload)
        self.assertEqual(body['entry']['actor_username'], 'admin')
        self.assertTrue(body['debug_info']['identity_overridden'])

    def test_note_lands_in_the_trail_looking_platform_written(self):
        self.client.post(
            '/api/audit/note',
            headers=self._auth(self.customer_token),
            json={'details': 'clean looking', 'actor_username': 'admin'},
        )

        planted = self.store.find_matching('AUDIT_NOTE_ADDED')
        self.assertTrue(planted)
        self.assertEqual(planted[-1]['actor_username'], 'admin')
        self.assertEqual(planted[-1]['action'], 'note')

    def test_console_paints_untrusted_fields_with_inner_html(self):
        with open(os.path.join(REPO_ROOT, 'static', 'audit.js'), encoding='utf-8') as handle:
            source = handle.read()

        self.assertIn('searchInfo.innerHTML', source)
        self.assertIn('${entry.details', source)
        self.assertIn('${entry.user_agent', source)

    def test_no_content_security_policy_is_emitted(self):
        response = self.client.get('/admin/audit', headers=self._auth(self.admin_token))

        self.assertEqual(response.status_code, 200)
        self.assertNotIn('Content-Security-Policy', response.headers)

    def test_console_lists_the_documented_findings(self):
        response = self.client.get('/admin/audit', headers=self._auth(self.admin_token))

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Audit Trail', response.data)
        self.assertIn(b'AV-01', response.data)
        self.assertIn(b'AV-11', response.data)

    def test_console_is_admin_only(self):
        response = self.client.get('/admin/audit', headers=self._auth(self.customer_token))

        self.assertEqual(response.status_code, 403)

    def test_console_renders_for_an_admin_token(self):
        response = self.client.get('/admin/audit', headers=self._auth(self.admin_token))

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'audit.js', response.data)
        self.assertIn(b'audit.css', response.data)

    # ------------------------------------------------------------------
    # AV-08 · Log injection
    # ------------------------------------------------------------------

    def test_note_event_type_with_a_newline_forges_a_second_record(self):
        forged = (
            'AUDIT_NOTE_ADDED\n'
            '[2026-01-01 00:00:00] TRANSFER_INITIATED severity=INFO result=SUCCESS '
            'actor=admin target=ADMIN001 ip=10.0.0.1 ua=curl/8.4.0'
        )

        response = self.client.post(
            '/api/audit/note',
            headers=self._auth(self.admin_token),
            json={'details': 'forged transfer below', 'actor_username': 'admin', 'event_type': forged},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('\n', response.get_json()['entry']['event_type'])

        tail = self.client.get('/api/audit/tail?lines=5', headers=self._auth()).get_json()
        rendered = tail['lines'][-1]
        self.assertIn('\n', rendered)
        self.assertIn(
            '[2026-01-01 00:00:00] TRANSFER_INITIATED severity=INFO result=SUCCESS actor=admin',
            rendered,
        )
        self.assertEqual(len(tail['lines']), 1)

    def test_a_newline_in_a_client_supplied_field_splits_one_event_into_two_rows(self):
        forged = 'AUDIT_NOTE_ADDED\n[2026-01-01 00:00:00] TRANSFER_INITIATED actor=admin'

        self.client.post(
            '/api/audit/note',
            headers=self._auth(self.admin_token),
            json={'event_type': forged},
        )

        rows = self.client.get('/api/audit/logs', headers=self._auth()).get_json()
        self.assertEqual(rows['total'], 1)
        self.assertEqual(rows['count'], 1)

    def test_user_agent_field_forging_survives_the_rendered_line(self):
        response = self.client.post(
            '/login',
            json={'username': 'admin', 'password': 'wrong-password'},
            headers={'User-Agent': 'x severity=CRITICAL result=SUCCESS actor=admin'},
        )

        self.assertEqual(response.status_code, 401)

        failures = self.store.find_matching('LOGIN_FAILED')
        self.assertEqual(failures[-1]['user_agent'], 'x severity=CRITICAL result=SUCCESS actor=admin')

        with self.app_module.app.test_request_context('/api/audit/tail'):
            line = self.audit_module.render_audit_line(failures[-1])

        self.assertIn('severity=WARNING', line)
        self.assertIn('severity=CRITICAL', line)
        self.assertIn('actor=anonymous', line)
        self.assertIn('actor=admin', line)

    def test_record_event_stores_a_crlf_user_agent_verbatim(self):
        forged = 'curl/8.4.0\r\n[2026-01-01 00:00:00] LOGIN_SUCCESS actor=admin result=SUCCESS'

        with self.app_module.app.test_request_context('/login', method='POST'):
            self.audit_module.record_event(
                'LOGIN_FAILED',
                severity='WARNING',
                action='login',
                target='admin',
                result='DENIED',
                context=self.audit_module.build_log_context() | {'user_agent': forged},
            )

        failures = self.store.find_matching('LOGIN_FAILED')
        self.assertTrue(failures)
        self.assertEqual(failures[-1]['user_agent'], forged)

    def test_user_agent_crlf_forges_an_extra_record_in_the_tail(self):
        forged = 'curl/8.4.0\r\n[2026-01-01 00:00:00] LOGIN_SUCCESS actor=admin result=SUCCESS'

        with self.app_module.app.test_request_context('/login', method='POST'):
            self.audit_module.record_event(
                'LOGIN_FAILED',
                action='login',
                target='admin',
                result='DENIED',
                context=self.audit_module.build_log_context() | {'user_agent': forged},
            )

        response = self.client.get('/api/audit/tail?lines=10', headers=self._auth())

        lines = response.get_json()['lines']
        self.assertEqual(len(lines), 1)
        self.assertIn('\n', lines[0])
        self.assertIn('LOGIN_SUCCESS actor=admin result=SUCCESS', lines[0])

    def test_referer_is_stored_raw(self):
        forged = 'https://evil.example\r\n[2026-01-01 00:00:00] LOGIN_SUCCESS actor=admin'

        with self.app_module.app.test_request_context('/login', method='POST'):
            self.audit_module.record_event(
                'LOGIN_FAILED',
                action='login',
                target='admin',
                result='DENIED',
                context=self.audit_module.build_log_context() | {'referer': forged},
            )

        failures = self.store.find_matching('LOGIN_FAILED')
        self.assertEqual(failures[-1]['referer'], forged)

    def test_build_log_context_mirrors_headers_without_sanitizing(self):
        response = self.client.post(
            '/login',
            json={'username': 'admin', 'password': 'wrong-password'},
            headers={
                'User-Agent': 'poc-agent/1.0',
                'Referer': 'https://attacker.example/poc',
                'X-Request-Id': 'req-1234',
            },
        )

        self.assertEqual(response.status_code, 401)

        with self.app_module.app.test_request_context(
            '/login',
            method='POST',
            headers={'User-Agent': 'poc-agent/1.0', 'Referer': 'https://attacker.example/poc'},
        ):
            context = self.audit_module.build_log_context()

        self.assertEqual(context['user_agent'], 'poc-agent/1.0')
        self.assertEqual(context['referer'], 'https://attacker.example/poc')
        self.assertEqual(context['endpoint'], '/login')
        self.assertEqual(context['http_method'], 'POST')

    def test_x_forwarded_for_is_trusted_without_validation(self):
        response = self.client.post(
            '/login',
            json={'username': 'admin', 'password': 'wrong-password'},
            headers={'X-Forwarded-For': '10.0.0.1, 10.0.0.2'},
        )

        self.assertEqual(response.status_code, 401)
        failures = self.store.find_matching('LOGIN_FAILED')
        self.assertEqual(failures[-1]['ip_address'], '10.0.0.1')

    def test_sanitizer_seam_exists_and_is_never_invoked(self):
        self.assertTrue(callable(self.audit_module._sanitize_for_log))
        self.assertEqual(
            self.audit_module._sanitize_for_log('value\r\n[forged] line'),
            'value\r\n[forged] line',
        )

        with self.app_module.app.test_request_context('/login', method='POST'):
            self.audit_module.record_event(
                'LOGIN_FAILED',
                action='login',
                target='admin',
                result='DENIED',
                context=self.audit_module.build_log_context() | {'user_agent': 'keep\r\nme'},
            )

        failures = self.store.find_matching('LOGIN_FAILED')
        self.assertIn('\r\n', failures[-1]['user_agent'])

    # ------------------------------------------------------------------
    # AV-10 · Anti-forensic purge
    # ------------------------------------------------------------------

    def test_purge_announces_itself_and_then_deletes_the_announcement(self):
        self.store.add_entry(event_type='LOGIN_SUCCESS')

        response = self.client.post(
            '/admin/audit/purge',
            headers=self._auth(self.admin_token),
            json={'all': True},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.store.rows, [])

        announce_index = next(
            index for index, statement in enumerate(self.store.statements)
            if 'INSERT INTO audit_log' in statement and 'AUDIT_LOG_PURGED' in statement
        )
        delete_index = next(
            index for index, statement in enumerate(self.store.statements)
            if statement.startswith('DELETE FROM audit_log')
        )
        self.assertLess(announce_index, delete_index)

    def test_purge_never_archives_or_retains_anything(self):
        response = self.client.post(
            '/admin/audit/purge',
            headers=self._auth(),
            json={'all': True},
        )

        debug_info = response.get_json()['debug_info']
        self.assertFalse(debug_info['archived_before_delete'])
        self.assertIsNone(debug_info['retention_policy'])
        self.assertFalse(debug_info['self_record_survives'])

    def test_deleting_an_entry_leaves_no_record_of_the_deletion(self):
        entry = self.store.add_entry(event_type='LOGIN_FAILED')

        response = self.client.delete(
            f'/api/audit/logs/{entry["id"]}',
            headers=self._auth(self.admin_token),
        )

        self.assertIsNone(self.store.find(entry['id']))
        self.assertFalse(response.get_json()['debug_info']['deletion_logged'])
        self.assertFalse(self.store.find_matching('AUDIT_LOG_DELETED'))

    # ------------------------------------------------------------------
    # AV-11 · Unverifiable integrity
    # ------------------------------------------------------------------

    def test_signature_endpoint_reports_verified_for_an_unsigned_entry(self):
        entry = self.store.add_entry(signature=None)

        response = self.client.get(
            f'/api/audit/logs/{entry["id"]}/signature',
            headers=self._auth(self.admin_token),
        )

        body = response.get_json()
        integrity = body['integrity']
        self.assertTrue(integrity['verified'])
        self.assertFalse(integrity['checked'])
        self.assertFalse(integrity['signed'])
        self.assertIsNone(body['stored_signature'])
        self.assertFalse(body['debug_info']['signing_key_configured'])

    def test_signature_endpoint_still_reports_verified_after_the_row_changed(self):
        entry = self.store.add_entry()

        self.client.post(
            f'/admin/audit/logs/{entry["id"]}',
            headers=self._auth(self.admin_token),
            json={'details': 'tampered after the fact'},
        )

        response = self.client.get(
            f'/api/audit/logs/{entry["id"]}/signature',
            headers=self._auth(self.admin_token),
        )

        self.assertTrue(response.get_json()['integrity']['verified'])

    def test_integrity_sweep_counts_unsigned_entries_as_verified(self):
        for _ in range(4):
            self.store.add_entry()

        response = self.client.get(
            '/admin/audit/integrity-check?limit=100',
            headers=self._auth(self.admin_token),
        )

        integrity = response.get_json()['integrity']
        self.assertEqual(integrity['checked'], 4)
        self.assertEqual(integrity['unsigned'], 4)
        self.assertEqual(integrity['tampered'], 0)
        self.assertEqual(integrity['overall'], 'verified')

    def test_integrity_sweep_stays_green_over_an_empty_trail(self):
        self.store.add_entry(event_type='LOGIN_SUCCESS')

        self.client.post(
            '/admin/audit/purge',
            headers=self._auth(self.admin_token),
            json={'all': True},
        )

        response = self.client.get(
            '/admin/audit/integrity-check',
            headers=self._auth(self.admin_token),
        )

        integrity = response.get_json()['integrity']
        self.assertEqual(integrity['checked'], 0)
        self.assertEqual(integrity['tampered'], 0)
        self.assertEqual(integrity['overall'], 'verified')

    def test_stats_claims_verified_next_to_the_unsigned_counter(self):
        for _ in range(3):
            self.store.add_entry(signature=None)

        response = self.client.get('/api/audit/stats', headers=self._auth(self.admin_token))

        body = response.get_json()
        self.assertEqual(body['stats']['unsigned_entries'], 3)
        self.assertEqual(body['integrity']['unsigned_entries'], 3)
        self.assertEqual(body['integrity']['claimed_status'], 'verified')

    def test_record_event_never_writes_a_signature(self):
        self.client.post(
            '/login',
            json={'username': 'admin', 'password': 'wrong-password'},
        )

        failures = self.store.find_matching('LOGIN_FAILED')
        self.assertTrue(failures)
        self.assertIsNone(failures[-1]['signature'])

        inserts = [statement for statement in self.store.statements if 'INSERT INTO audit_log' in statement]
        self.assertNotIn('signature', inserts[0])

    # ------------------------------------------------------------------
    # AV-12 · CSRF
    # ------------------------------------------------------------------

    def test_mutating_routes_need_nothing_but_a_bearer_token(self):
        response = self.client.post(
            '/api/audit/note',
            headers=self._auth(),
            json={'details': 'no token, no origin, no referer check'},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request.headers.get('Origin'), None)
        self.assertEqual(response.request.headers.get('X-CSRF-Token'), None)

    def test_purge_is_reachable_with_a_cookie_session_only(self):
        self.client.set_cookie('localhost', 'token', self.admin_token)

        response = self.client.post(
            '/admin/audit/purge',
            data='{"all": true}',
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['scope'], 'all')
        self.client.delete_cookie('localhost', 'token')

    def test_no_csrf_or_origin_check_exists_in_the_module(self):
        with open(os.path.join(REPO_ROOT, 'audit_log.py'), encoding='utf-8') as handle:
            source = handle.read().lower()

        self.assertNotIn('csrf_token', source)
        self.assertNotIn('xsrf', source)
        self.assertNotIn("headers.get('origin')", source)
        self.assertNotIn('same_site', source)

        with open(os.path.join(REPO_ROOT, 'templates', 'audit_admin.html'), encoding='utf-8') as handle:
            self.assertNotIn('csrf', handle.read().lower())

    # ------------------------------------------------------------------
    # AV-13 · HTTP parameter tampering
    # ------------------------------------------------------------------

    def test_jwt_is_accepted_from_the_query_string(self):
        response = self.client.get(f'/api/audit/logs?token={self.customer_token}')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['debug_info']['generated_by'], 'mallory')

    def test_paging_bounds_reach_the_statement_verbatim(self):
        self.client.get('/api/audit/logs?limit=25&offset=50', headers=self._auth())

        self.assertIn('LIMIT 25 OFFSET 50', self.store.any_statement())

    def test_note_identity_is_client_supplied(self):
        response = self.client.post(
            '/api/audit/note',
            headers=self._auth(self.customer_token),
            json={'actor_id': 1, 'actor_username': 'admin', 'details': 'planted'},
        )

        debug_info = response.get_json()['debug_info']
        self.assertEqual(debug_info['recorded_actor']['user_id'], 1)
        self.assertEqual(debug_info['recorded_actor']['username'], 'admin')
        self.assertEqual(debug_info['authenticated_as'], 'mallory')
        self.assertTrue(debug_info['identity_overridden'])

    def test_note_result_field_is_client_supplied(self):
        response = self.client.post(
            '/api/audit/note',
            headers=self._auth(),
            json={'result': 'SUCCESS', 'event_type': 'ACCOUNT_DELETED'},
        )

        entry = response.get_json()['entry']
        self.assertEqual(entry['event_type'], 'ACCOUNT_DELETED')
        self.assertEqual(entry['result'], 'SUCCESS')

    # ------------------------------------------------------------------
    # Instrumentation of the existing flows
    # ------------------------------------------------------------------

    def test_successful_login_is_recorded(self):
        response = self.client.post(
            '/login',
            json={'username': 'admin', 'password': 'admin123'},
        )

        self.assertEqual(response.status_code, 200)

        successes = self.store.find_matching('LOGIN_SUCCESS')
        self.assertTrue(successes)
        self.assertEqual(successes[-1]['actor_username'], 'admin')
        self.assertEqual(successes[-1]['target'], 'admin')
        self.assertEqual(successes[-1]['endpoint'], '/login')
        self.assertEqual(successes[-1]['http_method'], 'POST')

    def test_failed_login_is_recorded_with_the_attempted_username(self):
        response = self.client.post(
            '/login',
            json={'username': 'admin', 'password': 'wrong-password'},
        )

        self.assertEqual(response.status_code, 401)

        failures = self.store.find_matching('LOGIN_FAILED')
        self.assertTrue(failures)
        self.assertEqual(failures[-1]['target'], 'admin')
        self.assertEqual(failures[-1]['result'], 'DENIED')
        self.assertEqual(failures[-1]['severity'], 'WARNING')

    def test_suspended_login_is_recorded_as_denied(self):
        self.users.suspend('mallory')

        response = self.client.post(
            '/login',
            json={'username': 'mallory', 'password': 'mallory123'},
        )

        self.assertEqual(response.status_code, 403)

        failures = self.store.find_matching('LOGIN_FAILED')
        self.assertTrue(failures)
        self.assertEqual(failures[-1]['result'], 'DENIED')
        self.assertEqual(failures[-1]['details'], 'account suspended')

    def test_registration_is_recorded(self):
        response = self.client.post(
            '/register',
            json={'username': 'newcomer', 'password': 'secret123'},
        )

        self.assertEqual(response.status_code, 200)

        created = self.store.find_matching('ACCOUNT_CREATED')
        self.assertTrue(created)
        self.assertEqual(created[-1]['target'], 'newcomer')
        self.assertEqual(created[-1]['action'], 'register')

    def test_bio_update_is_recorded_for_the_authenticated_actor(self):
        response = self.client.post(
            '/update_bio',
            headers=self._auth(self.customer_token),
            json={'bio': 'hello trail'},
        )

        self.assertEqual(response.status_code, 200)

        updates = self.store.find_matching('PROFILE_UPDATED')
        self.assertTrue(updates)
        self.assertEqual(updates[-1]['actor_username'], 'mallory')
        self.assertEqual(str(updates[-1]['actor_id']), '7')
        self.assertEqual(updates[-1]['details'], 'bio_length=11')

    def test_denied_transfer_is_recorded(self):
        response = self.client.post(
            '/transfer',
            headers=self._auth(self.customer_token),
            json={'amount': 5000, 'to_account': 'ADMIN001'},
        )

        self.assertEqual(response.status_code, 400)

        transfers = self.store.find_matching('TRANSFER_INITIATED')
        self.assertTrue(transfers)
        self.assertEqual(transfers[-1]['result'], 'DENIED')
        self.assertEqual(transfers[-1]['severity'], 'WARNING')

    def test_every_recorded_event_carries_the_request_context(self):
        self.client.post(
            '/login',
            json={'username': 'admin', 'password': 'wrong-password'},
            headers={
                'User-Agent': 'poc-agent/1.0',
                'Referer': 'https://attacker.example/poc',
                'X-Request-Id': 'req-1234',
            },
        )

        failures = self.store.find_matching('LOGIN_FAILED')
        self.assertEqual(failures[-1]['user_agent'], 'poc-agent/1.0')
        self.assertEqual(failures[-1]['referer'], 'https://attacker.example/poc')
        self.assertEqual(failures[-1]['request_id'], 'req-1234')
        self.assertEqual(failures[-1]['http_method'], 'POST')
        self.assertEqual(failures[-1]['endpoint'], '/login')

    def test_recorded_event_is_mirrored_to_stdout(self):
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.client.post(
                '/login',
                json={'username': 'admin', 'password': 'admin123'},
            )

        output = buffer.getvalue()
        self.assertIn('LOGIN_SUCCESS', output)
        self.assertIn('actor=admin', output)

    def test_a_broken_audit_write_does_not_break_the_request(self):
        with patch.object(self.audit_module, 'execute_query', side_effect=RuntimeError('audit down')):
            response = self.client.post(
                '/login',
                json={'username': 'admin', 'password': 'admin123'},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['status'], 'success')


if __name__ == '__main__':
    unittest.main()
