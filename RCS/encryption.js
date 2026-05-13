// =============================================================================
// SECTION 1: ENCRYPTION UTILITY
// File: utils/encryption.js
// Developer: Albert Baral
// Description: AES-256 encryption/decryption for files at rest.
//              Each file gets a unique key, which is itself encrypted
//              using a server-side MASTER_KEY from environment variables.
// =============================================================================

const crypto = require("crypto");

const ALGORITHM = "aes-256-cbc";
const MASTER_KEY = Buffer.from(process.env.MASTER_KEY, "hex"); // 32-byte hex key in .env

// -----------------------------------------------------------------------------
// 1a. Generate a unique AES-256 key and IV for a single file
// -----------------------------------------------------------------------------
function generateFileKey() {
  return {
    fileKey: crypto.randomBytes(32), // 256-bit unique key per file
    iv: crypto.randomBytes(16),      // 128-bit initialization vector
  };
}

// -----------------------------------------------------------------------------
// 1b. Encrypt the file's unique key using the master key
//     Stores encrypted key + keyIV in the database (encryption_key_enc, iv)
// -----------------------------------------------------------------------------
function encryptFileKey(fileKey) {
  const keyIV = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, MASTER_KEY, keyIV);
  const encryptedKey = Buffer.concat([cipher.update(fileKey), cipher.final()]);

  return {
    encryption_key_enc: encryptedKey.toString("hex"), // store in DB
    keyIV: keyIV.toString("hex"),                     // store in DB alongside
  };
}

// -----------------------------------------------------------------------------
// 1c. Decrypt the file key from DB back to raw Buffer
// -----------------------------------------------------------------------------
function decryptFileKey(encryptedKeyHex, keyIVHex) {
  const keyIV = Buffer.from(keyIVHex, "hex");
  const encryptedKey = Buffer.from(encryptedKeyHex, "hex");
  const decipher = crypto.createDecipheriv(ALGORITHM, MASTER_KEY, keyIV);
  return Buffer.concat([decipher.update(encryptedKey), decipher.final()]);
}

// -----------------------------------------------------------------------------
// 1d. Encrypt file buffer before writing to disk
// -----------------------------------------------------------------------------
function encryptFile(fileBuffer, fileKey, iv) {
  const cipher = crypto.createCipheriv(ALGORITHM, fileKey, iv);
  return Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
}

// -----------------------------------------------------------------------------
// 1e. Decrypt file buffer when user downloads
// -----------------------------------------------------------------------------
function decryptFile(encryptedBuffer, fileKey, iv) {
  const decipher = crypto.createDecipheriv(ALGORITHM, fileKey, iv);
  return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
}

module.exports = {
  generateFileKey,
  encryptFileKey,
  decryptFileKey,
  encryptFile,
  decryptFile,
};
