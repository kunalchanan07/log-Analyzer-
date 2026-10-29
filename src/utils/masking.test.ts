import test from 'node:test';
import assert from 'node:assert/strict';
import { redactSensitiveData } from './masking';

test('redactSensitiveData redacts password in query and key-value formats', () => {
  const line = 'GET /login?user=admin&password=SuperSecretPassword123 HTTP/1.1';
  const redacted = redactSensitiveData(line);
  assert.ok(!redacted.includes('SuperSecretPassword123'));
  assert.ok(redacted.includes('[REDACTED_PASSWORD]'));
});

test('redactSensitiveData redacts Bearer JWT tokens', () => {
  const line = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSecret';
  const redacted = redactSensitiveData(line);
  assert.ok(!redacted.includes('doNotLeakThisSecret'));
  assert.ok(redacted.includes('Bearer [REDACTED_JWT_TOKEN]'));
});

test('redactSensitiveData redacts API keys and session IDs', () => {
  const line = 'api_key=sk_live_984719827391823791823&PHPSESSID=abcdef1234567890abcdef1234567890';
  const redacted = redactSensitiveData(line);
  assert.ok(!redacted.includes('sk_live_984719827391823791823'));
  assert.ok(redacted.includes('[REDACTED_API_KEY]'));
  assert.ok(redacted.includes('[REDACTED_SESSION_ID]'));
});
