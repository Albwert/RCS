# Security Module — Remote Cloud Storage System
**Developer:** Albert Baral (Roll No: 43)  
**Project:** Remote Cloud Storage System — Tribhuvan University  
**Supervisor:** Bindu Aryal

---

## What This Module Covers

| Section | File | Purpose |
|---------|------|---------|
| 1 | `utils/encryption.js` | AES-256 file encryption/decryption |
| 2 | `middleware/authMiddleware.js` | JWT token verification |
| 3 | `middleware/securityMiddleware.js` | Rate limiting, Helmet headers, input validation |
| 4 | `utils/fileHandler.js` | Encrypted file save/read/delete |
| 5 | `tests/encryption.test.js` | Jest unit tests |
| 6 | `config/.env.example` | Environment variable template |
| 7 | `config/generateKeys.js` | One-time key generation script |

---

## Setup Instructions

### 1. Install dependencies
```bash
npm install jsonwebtoken bcrypt helmet express-rate-limit express-validator node-mocks-http jest
```

### 2. Generate your keys
```bash
node config/generateKeys.js
```
Copy the output into a `.env` file at your project root.

### 3. Run tests
```bash
npx jest tests/encryption.test.js --verbose
```

---

## How Encryption Works (for defense)

```
Upload Flow:
  User File
      ↓
  generateFileKey()  →  unique AES-256 key + IV per file
      ↓
  encryptFile()      →  file encrypted on disk (.enc)
      ↓
  encryptFileKey()   →  file key wrapped with MASTER_KEY
      ↓
  DB stores: encryption_key_enc, iv, keyIV, storage_path

Download Flow:
  DB record
      ↓
  decryptFileKey()   →  recover original file key
      ↓
  decryptFile()      →  recover original file bytes
      ↓
  Send to user
```

---

## Security Design Decisions

| Decision | Reason |
|----------|--------|
| Per-file unique keys | If one key leaks, other files stay safe |
| Master key in `.env` | Never stored in DB or codebase |
| AES-256-CBC | Industry standard, supported natively in Node.js crypto |
| IV stored in DB | IV is not secret; it's needed for decryption |
| bcrypt for passwords | One-way hash; even DB leak doesn't expose passwords |
| Helmet.js | Prevents XSS, clickjacking via HTTP headers |
| Rate limiting | Blocks brute-force on login (10 attempts / 15 min) |

---

## Prototype Limitation (state this at defense)

> The master key is stored as an environment variable, which is acceptable  
> for a prototype. A production system would use a dedicated key management  
> service such as AWS KMS or HashiCorp Vault.
