const crypto = require('crypto');

function getEncryptionKey() {
  const raw = String(process.env.DATA_ENCRYPTION_KEY || '').trim();
  if (!raw) return null;
  // Accept base64 or base64url.
  const b64 = raw.replace(/-/g, '+').replace(/_/g, '/');
  const buf = Buffer.from(b64, 'base64');
  if (buf.length !== 32) {
    throw new Error('DATA_ENCRYPTION_KEY must be 32 bytes (base64-encoded) for AES-256-GCM.');
  }
  return buf;
}

function encryptString(plaintext) {
  const key = getEncryptionKey();
  if (!key) return String(plaintext || '');
  const text = String(plaintext || '');
  if (!text) return '';

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Format: enc:v1:<iv_b64url>:<tag_b64url>:<ct_b64url>
  const b64url = (b) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  return `enc:v1:${b64url(iv)}:${b64url(tag)}:${b64url(ciphertext)}`;
}

function decryptString(value) {
  const key = getEncryptionKey();
  const v = String(value || '');
  if (!v) return '';
  if (!v.startsWith('enc:v1:')) return v;
  if (!key) {
    // Key missing; fail closed (treat as unreadable).
    return '';
  }

  const parts = v.split(':');
  if (parts.length !== 5) return '';

  const fromB64Url = (s) => {
    const b64 = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
    const pad = '='.repeat((4 - (b64.length % 4)) % 4);
    return Buffer.from(b64 + pad, 'base64');
  };

  const iv = fromB64Url(parts[2]);
  const tag = fromB64Url(parts[3]);
  const ciphertext = fromB64Url(parts[4]);

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString('utf8');
  } catch {
    return '';
  }
}

function maybeEncrypt(value) {
  const v = String(value || '');
  if (!v) return '';
  if (v.startsWith('enc:v1:')) return v;
  // If no key, keep plaintext.
  if (!String(process.env.DATA_ENCRYPTION_KEY || '').trim()) return v;
  return encryptString(v);
}

function maybeDecrypt(value) {
  const v = String(value || '');
  if (!v) return '';
  if (!v.startsWith('enc:v1:')) return v;
  return decryptString(v);
}

module.exports = {
  getEncryptionKey,
  encryptString,
  decryptString,
  maybeEncrypt,
  maybeDecrypt
};
