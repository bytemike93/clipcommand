const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

require('dotenv').config();

const ENCRYPTED_PREFIX = 'enc:';
const HASH_ALGO = 'sha256';
const ENCRYPTION_SECRET = process.env.TOKEN_ENCRYPTION_KEY;

if (!ENCRYPTION_SECRET || ENCRYPTION_SECRET.length < 16) {
  throw new Error('TOKEN_ENCRYPTION_KEY environment variable must be set and at least 16 characters long.');
}

const encryptionKey = crypto.scryptSync(ENCRYPTION_SECRET, 'clipcommand', 32);

function encrypt(value) {
  if (!value) return null;
  if (value.startsWith(ENCRYPTED_PREFIX)) return value;

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return `${ENCRYPTED_PREFIX}${Buffer.concat([iv, authTag, encrypted]).toString('base64')}`;
}

function decrypt(value) {
  if (!value) return null;
  if (!value.startsWith(ENCRYPTED_PREFIX)) return value;

  try {
    const data = Buffer.from(value.slice(ENCRYPTED_PREFIX.length), 'base64');
    const iv = data.subarray(0, 12);
    const authTag = data.subarray(12, 28);
    const encrypted = data.subarray(28);

    const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (err) {
    console.error('Decrypt failed, value will be ignored.', err);
    return null;
  }
}

function hashToken(token) {
  return crypto.createHash(HASH_ALGO).update(token, 'utf8').digest('hex');
}

const db = new Database(path.join(__dirname, 'tokens.db'));

function ensureSchema() {
  try {
    db.exec(
      `
      CREATE TABLE IF NOT EXISTS tokens (
        user_id TEXT PRIMARY KEY,
        api_token TEXT NOT NULL,
        api_token_hash TEXT UNIQUE,
        access_token TEXT NOT NULL,
        refresh_token TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
      `
    );

    const columns = db.prepare(`PRAGMA table_info(tokens)`).all();
    const hasHashColumn = columns.some((col) => col.name === 'api_token_hash');

    if (!hasHashColumn) {
      try {
        db.exec(`ALTER TABLE tokens ADD COLUMN api_token_hash TEXT`);
      } catch (alterErr) {
        if (!String(alterErr.message || '').includes('duplicate column name')) {
          console.error('ALTER TABLE tokens für api_token_hash fehlgeschlagen:', alterErr);
        }
      }
    }

    try {
      db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_tokens_api_token_hash ON tokens(api_token_hash)`);
    } catch (indexErr) {
      console.error('Konnte Index für api_token_hash nicht erzeugen:', indexErr);
    }

    migrateLegacyRows();
  } catch (err) {
    console.error('Konnte Basistabelle nicht anlegen:', err);
  }
}

function migrateLegacyRows() {
  let rows;
  try {
    rows = db
      .prepare(`SELECT user_id, api_token, api_token_hash, access_token, refresh_token FROM tokens`)
      .all();
  } catch (err) {
    console.error('Legacy-Migration konnte Daten nicht laden:', err);
    return;
  }

  const updateStmt = db.prepare(
    `UPDATE tokens SET api_token = ?, api_token_hash = ?, access_token = ?, refresh_token = ? WHERE user_id = ?`
  );

  rows.forEach((row) => {
    if (!row.api_token) return;

    const plainApiToken = decrypt(row.api_token);
    if (!plainApiToken) {
      console.warn('API-Token konnte nicht entschlüsselt werden, Nutzer muss neu autorisieren:', {
        user_id: row.user_id
      });
      return;
    }

    const hashed = hashToken(plainApiToken);
    const encryptedApiToken = row.api_token.startsWith(ENCRYPTED_PREFIX)
      ? row.api_token
      : encrypt(plainApiToken);

    const plainAccess = decrypt(row.access_token);
    if (!plainAccess) {
      console.warn('Access-Token konnte nicht entschlüsselt werden, Eintrag wird übersprungen.', {
        user_id: row.user_id
      });
      return;
    }

    const encryptedAccess =
      row.access_token && row.access_token.startsWith(ENCRYPTED_PREFIX)
        ? row.access_token
        : encrypt(plainAccess);

    const plainRefresh = row.refresh_token ? decrypt(row.refresh_token) : null;
    const encryptedRefresh =
      row.refresh_token && row.refresh_token.startsWith(ENCRYPTED_PREFIX)
        ? row.refresh_token
        : plainRefresh
        ? encrypt(plainRefresh)
        : null;

    const needsUpdate =
      row.api_token !== encryptedApiToken ||
      row.api_token_hash !== hashed ||
      row.access_token !== encryptedAccess ||
      row.refresh_token !== encryptedRefresh;

    if (needsUpdate) {
      try {
        updateStmt.run(encryptedApiToken, hashed, encryptedAccess, encryptedRefresh, row.user_id);
      } catch (updateErr) {
        console.error('Migration-Update fehlgeschlagen:', {
          user_id: row.user_id,
          err: updateErr
        });
      }
    }
  });
}

ensureSchema();

function setToken(user_id, access_token, refresh_token, callback) {
  if (!user_id || !access_token) {
    const err = new Error('user_id und access_token sind erforderlich.');
    if (callback) callback(err);
    return;
  }

  try {
    const encryptedAccess = encrypt(access_token);
    const encryptedRefresh = refresh_token ? encrypt(refresh_token) : null;

    const row = db.prepare(`SELECT api_token FROM tokens WHERE user_id = ?`).get(user_id);

    let apiTokenPlain = null;
    let isNew = true;

    if (row && row.api_token) {
      apiTokenPlain = decrypt(row.api_token);
      if (apiTokenPlain) {
        isNew = false;
      } else {
        console.warn('Bestehender API-Token unlesbar, es wird ein neuer Token erstellt.', {
          user_id
        });
      }
    }

    if (!apiTokenPlain) {
      apiTokenPlain = uuidv4();
      isNew = true;
    }

    const encryptedApiToken = encrypt(apiTokenPlain);
    const apiTokenHash = hashToken(apiTokenPlain);

    db.prepare(
      `INSERT INTO tokens (user_id, api_token, api_token_hash, access_token, refresh_token, updated_at)
       VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(user_id) DO UPDATE SET
         api_token = excluded.api_token,
         api_token_hash = excluded.api_token_hash,
         access_token = excluded.access_token,
         refresh_token = excluded.refresh_token,
         updated_at = CURRENT_TIMESTAMP`
    ).run(user_id, encryptedApiToken, apiTokenHash, encryptedAccess, encryptedRefresh);

    if (callback) callback(null, apiTokenPlain, { isNew });
  } catch (writeErr) {
    if (callback) callback(writeErr);
  }
}

function setTokenAsync(user_id, access_token, refresh_token) {
  return new Promise((resolve, reject) => {
    setToken(user_id, access_token, refresh_token, (err, apiToken, meta) => {
      if (err) return reject(err);
      resolve({ apiToken, meta });
    });
  });
}

function getToken(user_id, callback) {
  try {
    const row = db.prepare(`SELECT access_token FROM tokens WHERE user_id = ?`).get(user_id);
    const accessToken = row ? decrypt(row.access_token) : null;
    callback(null, accessToken);
  } catch (err) {
    callback(err, null);
  }
}

function getTokenByApiToken(api_token, callback) {
  if (!api_token) {
    callback(new Error('API-Token fehlt'), null, null, null);
    return;
  }

  try {
    const apiTokenHash = hashToken(api_token);
    const row = db
      .prepare(`SELECT user_id, access_token, refresh_token FROM tokens WHERE api_token_hash = ?`)
      .get(apiTokenHash);

    if (!row) {
      callback(null, null, null, null);
      return;
    }

    callback(
      null,
      row.user_id,
      decrypt(row.access_token),
      row.refresh_token ? decrypt(row.refresh_token) : null
    );
  } catch (err) {
    callback(err, null, null, null);
  }
}

function getTokenByApiTokenAsync(api_token) {
  return new Promise((resolve, reject) => {
    getTokenByApiToken(api_token, (err, userId, accessToken, refreshToken) => {
      if (err) return reject(err);
      resolve([userId, accessToken, refreshToken]);
    });
  });
}

function deleteTokenByUserId(user_id) {
  return new Promise((resolve, reject) => {
    try {
      const result = db.prepare(`DELETE FROM tokens WHERE user_id = ?`).run(user_id);
      resolve(result.changes > 0);
    } catch (err) {
      reject(err);
    }
  });
}

module.exports = {
  setToken,
  setTokenAsync,
  getToken,
  getTokenByApiToken,
  getTokenByApiTokenAsync,
  deleteTokenByUserId
};
