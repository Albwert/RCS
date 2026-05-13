// =============================================================================
// SECTION 4: SECURE FILE UPLOAD HANDLER
// File: utils/fileHandler.js
// Developer: Albert Baral
// Description: Handles file upload with encryption before saving to disk.
//              Also handles decryption on download.
//              Works with Multer (Aayush's setup) for multipart parsing.
// =============================================================================

const fs   = require("fs");
const path = require("path");
const {
  generateFileKey,
  encryptFileKey,
  decryptFileKey,
  encryptFile,
  decryptFile,
} = require("./encryption");

const STORAGE_DIR = path.join(__dirname, "../../storage/encrypted");

// Ensure storage directory exists
if (!fs.existsSync(STORAGE_DIR)) {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

// -----------------------------------------------------------------------------
// 4a. Save uploaded file to disk with AES-256 encryption
//     Returns metadata to be stored in the DB (File table)
// -----------------------------------------------------------------------------
async function saveEncryptedFile(fileBuffer, originalFilename, userId) {
  // Generate unique key and IV for this specific file
  const { fileKey, iv } = generateFileKey();

  // Encrypt the file content
  const encryptedBuffer = encryptFile(fileBuffer, fileKey, iv);

  // Encrypt the file key with master key for DB storage
  const { encryption_key_enc, keyIV } = encryptFileKey(fileKey);

  // Build a safe storage filename (not the original name → avoids path traversal)
  const storageFilename = `${userId}_${Date.now()}_${crypto.randomUUID()}.enc`;
  const storagePath = path.join(STORAGE_DIR, storageFilename);

  // Write encrypted file to disk
  fs.writeFileSync(storagePath, encryptedBuffer);

  // Return DB metadata — DO NOT store raw fileKey anywhere
  return {
    storage_path:       storageFilename,
    encryption_key_enc: encryption_key_enc,
    iv:                 iv.toString("hex"),
    keyIV:              keyIV,
  };
}

// -----------------------------------------------------------------------------
// 4b. Read and decrypt file from disk for download
//     Accepts the file's DB row as input
// -----------------------------------------------------------------------------
function readDecryptedFile(fileRecord) {
  const storagePath = path.join(STORAGE_DIR, fileRecord.storage_path);

  if (!fs.existsSync(storagePath)) {
    throw new Error("File not found on storage.");
  }

  const encryptedBuffer = fs.readFileSync(storagePath);

  // Recover the original file key
  const fileKey = decryptFileKey(fileRecord.encryption_key_enc, fileRecord.keyIV);
  const iv      = Buffer.from(fileRecord.iv, "hex");

  // Decrypt and return raw buffer
  return decryptFile(encryptedBuffer, fileKey, iv);
}

// -----------------------------------------------------------------------------
// 4c. Delete encrypted file from disk (on user delete request)
// -----------------------------------------------------------------------------
function deleteStoredFile(storagePath) {
  const fullPath = path.join(STORAGE_DIR, storagePath);
  if (fs.existsSync(fullPath)) {
    fs.unlinkSync(fullPath);
  }
}

module.exports = { saveEncryptedFile, readDecryptedFile, deleteStoredFile };
