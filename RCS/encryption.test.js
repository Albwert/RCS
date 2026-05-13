// =============================================================================
// SECTION 5: UNIT TESTS
// File: tests/encryption.test.js
// Developer: Albert Baral
// Description: Jest unit tests for all encryption functions and
//              auth middleware. Run with: npx jest
// =============================================================================

// Setup fake environment before importing modules
process.env.MASTER_KEY = require("crypto").randomBytes(32).toString("hex");
process.env.JWT_SECRET  = "test_jwt_secret_for_unit_tests";

const crypto = require("crypto");
const jwt    = require("jsonwebtoken");
const httpMocks = require("node-mocks-http");

const {
  generateFileKey,
  encryptFileKey,
  decryptFileKey,
  encryptFile,
  decryptFile,
} = require("../utils/encryption");

const { authenticateToken } = require("../middleware/authMiddleware");

// =============================================================================
// TEST SUITE 1: Key Generation
// =============================================================================
describe("1. generateFileKey()", () => {
  test("returns a 32-byte fileKey", () => {
    const { fileKey } = generateFileKey();
    expect(fileKey).toBeInstanceOf(Buffer);
    expect(fileKey.length).toBe(32);
  });

  test("returns a 16-byte iv", () => {
    const { iv } = generateFileKey();
    expect(iv).toBeInstanceOf(Buffer);
    expect(iv.length).toBe(16);
  });

  test("two calls produce different keys (no collisions)", () => {
    const a = generateFileKey();
    const b = generateFileKey();
    expect(a.fileKey.toString("hex")).not.toBe(b.fileKey.toString("hex"));
    expect(a.iv.toString("hex")).not.toBe(b.iv.toString("hex"));
  });
});

// =============================================================================
// TEST SUITE 2: File Key Encryption / Decryption (Master Key wrapping)
// =============================================================================
describe("2. encryptFileKey() / decryptFileKey()", () => {
  test("encrypted key is a hex string (not raw bytes)", () => {
    const { fileKey } = generateFileKey();
    const { encryption_key_enc } = encryptFileKey(fileKey);
    expect(typeof encryption_key_enc).toBe("string");
    expect(encryption_key_enc).toMatch(/^[0-9a-f]+$/i);
  });

  test("decrypting returns the original file key exactly", () => {
    const { fileKey } = generateFileKey();
    const { encryption_key_enc, keyIV } = encryptFileKey(fileKey);
    const recovered = decryptFileKey(encryption_key_enc, keyIV);
    expect(recovered.toString("hex")).toBe(fileKey.toString("hex"));
  });

  test("tampered encrypted key throws on decryption", () => {
    const { fileKey } = generateFileKey();
    const { encryption_key_enc, keyIV } = encryptFileKey(fileKey);
    const tampered = encryption_key_enc.slice(0, -2) + "ff"; // flip last byte
    expect(() => decryptFileKey(tampered, keyIV)).toThrow();
  });
});

// =============================================================================
// TEST SUITE 3: File Encryption / Decryption
// =============================================================================
describe("3. encryptFile() / decryptFile()", () => {
  test("encrypted output differs from original plaintext", () => {
    const { fileKey, iv } = generateFileKey();
    const original  = Buffer.from("Hello, this is a secret file.");
    const encrypted = encryptFile(original, fileKey, iv);
    expect(encrypted.toString("hex")).not.toBe(original.toString("hex"));
  });

  test("decrypting gives back exact original content", () => {
    const { fileKey, iv } = generateFileKey();
    const original  = Buffer.from("Hello, this is a secret file.");
    const encrypted = encryptFile(original, fileKey, iv);
    const decrypted = decryptFile(encrypted, fileKey, iv);
    expect(decrypted.toString()).toBe(original.toString());
  });

  test("wrong key fails to decrypt correctly", () => {
    const { fileKey, iv } = generateFileKey();
    const { fileKey: wrongKey } = generateFileKey();
    const original  = Buffer.from("Secret data");
    const encrypted = encryptFile(original, fileKey, iv);
    expect(() => decryptFile(encrypted, wrongKey, iv)).toThrow();
  });

  test("works on larger binary buffer (simulated file)", () => {
    const { fileKey, iv } = generateFileKey();
    const bigFile   = crypto.randomBytes(1024 * 100); // 100KB
    const encrypted = encryptFile(bigFile, fileKey, iv);
    const decrypted = decryptFile(encrypted, fileKey, iv);
    expect(decrypted.toString("hex")).toBe(bigFile.toString("hex"));
  });
});

// =============================================================================
// TEST SUITE 4: JWT Auth Middleware
// =============================================================================
describe("4. authenticateToken() middleware", () => {
  const payload = { userId: 1, username: "albert" };

  function makeToken(expiresIn = "1h") {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn });
  }

  test("valid token calls next() and attaches user to req", () => {
    const token = makeToken();
    const req   = httpMocks.createRequest({
      headers: { authorization: `Bearer ${token}` },
    });
    const res  = httpMocks.createResponse();
    const next = jest.fn();

    authenticateToken(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(req.user.userId).toBe(1);
  });

  test("missing token returns 401", () => {
    const req  = httpMocks.createRequest({ headers: {} });
    const res  = httpMocks.createResponse();
    const next = jest.fn();

    authenticateToken(req, res, next);

    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test("expired token returns 401 with clear message", () => {
    const token = makeToken("1ms");

    return new Promise((resolve) => {
      setTimeout(() => {
        const req  = httpMocks.createRequest({
          headers: { authorization: `Bearer ${token}` },
        });
        const res  = httpMocks.createResponse();
        const next = jest.fn();

        authenticateToken(req, res, next);

        expect(res.statusCode).toBe(401);
        const data = res._getJSONData();
        expect(data.error).toMatch(/expired/i);
        resolve();
      }, 50);
    });
  });

  test("tampered token returns 403", () => {
    const token   = makeToken();
    const tampered = token.slice(0, -5) + "XXXXX";
    const req  = httpMocks.createRequest({
      headers: { authorization: `Bearer ${tampered}` },
    });
    const res  = httpMocks.createResponse();
    const next = jest.fn();

    authenticateToken(req, res, next);

    expect(res.statusCode).toBe(403);
  });
});
