// =============================================================================
// SECTION 2: JWT AUTHENTICATION MIDDLEWARE
// File: middleware/authMiddleware.js
// Developer: Albert Baral
// Description: Verifies JWT tokens on protected routes.
//              Works with Aayush's token issuance in the auth controller.
// =============================================================================

const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET;

// -----------------------------------------------------------------------------
// 2a. Protect route — verifies Bearer token in Authorization header
// -----------------------------------------------------------------------------
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // "Bearer <token>"

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // attach user payload to request
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expired. Please log in again." });
    }
    return res.status(403).json({ error: "Invalid token." });
  }
}

// -----------------------------------------------------------------------------
// 2b. Optional auth — attaches user if token present, but doesn't block
//     Used for public share links that MAY have an authenticated user
// -----------------------------------------------------------------------------
function optionalAuth(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token) {
    try {
      req.user = jwt.verify(token, JWT_SECRET);
    } catch {
      req.user = null; // invalid token → treat as guest
    }
  }
  next();
}

module.exports = { authenticateToken, optionalAuth };
