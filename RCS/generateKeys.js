// =============================================================================
// SECTION 7: KEY GENERATION SCRIPT
// File: config/generateKeys.js
// Developer: Albert Baral
// Description: Run once during setup to generate secure keys.
//              Copy the output into your .env file.
//              Usage: node config/generateKeys.js
// =============================================================================

const crypto = require("crypto");

console.log("\n===== Remote Cloud Storage — Key Generator =====\n");

const masterKey = crypto.randomBytes(32).toString("hex");
const jwtSecret = crypto.randomBytes(64).toString("hex");

console.log("Copy the lines below into your .env file:\n");
console.log(`MASTER_KEY=${masterKey}`);
console.log(`JWT_SECRET=${jwtSecret}`);
console.log("\n⚠  Keep these secret. Never commit to Git.\n");
