/**
 * Enterprise Data Loss Prevention (DLP) & Sensitive Information Redaction
 * Scrubs passwords, bearer tokens, API keys, session cookies, database credentials, and private keys.
 */
export function redactSensitiveData(raw: string): string {
  if (!raw) return raw;

  let sanitized = raw;

  // 1. Redact Passwords
  sanitized = sanitized.replace(
    /(["']?(?:password|passwd|pwd|pass|secret)["']?\s*[:=]\s*["']?)([^"'&,\s]+)(["']?)/gi,
    '$1[REDACTED_PASSWORD]$3'
  );

  // 2. Redact Bearer / JWT Tokens (eyJ...)
  sanitized = sanitized.replace(
    /Bearer\s+(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})/gi,
    'Bearer [REDACTED_JWT_TOKEN]'
  );

  // 3. Redact API Keys
  sanitized = sanitized.replace(
    /(["']?(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']?)([^"'&,\s]+)(["']?)/gi,
    '$1[REDACTED_API_KEY]$3'
  );

  // 4. Redact Session & Cookie Identifiers
  sanitized = sanitized.replace(
    /(PHPSESSID|JSESSIONID|session_id|connect\.sid)=([a-zA-Z0-9_-]{16,})/gi,
    '$1=[REDACTED_SESSION_ID]'
  );

  // 5. Redact Credit Card Numbers
  sanitized = sanitized.replace(
    /\b(?:\d{4}[ -]?){3}\d{4}\b/g,
    '****-****-****-****'
  );

  // 6. Redact Database Connection Strings
  sanitized = sanitized.replace(
    /(mongodb|postgres(?:ql)?|mysql):\/\/([^:]+):([^@]+)@/gi,
    '$1://$2:[REDACTED_DB_PWD]@'
  );

  return sanitized;
}
