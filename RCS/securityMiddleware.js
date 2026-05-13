// =============================================================================
// SECTION 3: RATE LIMITING & SECURITY HEADERS
// File: middleware/securityMiddleware.js
// Developer: Albert Baral
// Description: Prevents brute-force attacks on login.
//              Adds HTTP security headers using Helmet.
//              Sanitizes user input to block injection attacks.
// =============================================================================

const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");

// -----------------------------------------------------------------------------
// 3a. Helmet — sets secure HTTP headers automatically
//     Blocks clickjacking, sniffing, XSS via headers
// -----------------------------------------------------------------------------
const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", "data:"],
    },
  },
  hsts: {
    maxAge: 31536000,           // 1 year
    includeSubDomains: true,
  },
});

// -----------------------------------------------------------------------------
// 3b. Rate limiter for login endpoint
//     Blocks brute-force password attacks
// -----------------------------------------------------------------------------
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15-minute window
  max: 10,                     // max 10 attempts per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many login attempts. Please try again after 15 minutes.",
  },
});

// -----------------------------------------------------------------------------
// 3c. General API rate limiter
//     Prevents abuse on all other endpoints
// -----------------------------------------------------------------------------
const generalRateLimiter = rateLimit({
  windowMs: 60 * 1000,         // 1-minute window
  max: 100,                    // 100 requests per IP per minute
  message: {
    error: "Too many requests. Please slow down.",
  },
});

// -----------------------------------------------------------------------------
// 3d. Input validation rules for registration
// -----------------------------------------------------------------------------
const validateRegister = [
  body("username")
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage("Username must be 3–30 characters.")
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage("Username can only contain letters, numbers, and underscores."),

  body("email")
    .trim()
    .isEmail()
    .withMessage("Invalid email address.")
    .normalizeEmail(),

  body("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters.")
    .matches(/[A-Z]/).withMessage("Password must contain an uppercase letter.")
    .matches(/[0-9]/).withMessage("Password must contain a number."),
];

// -----------------------------------------------------------------------------
// 3e. Input validation rules for login
// -----------------------------------------------------------------------------
const validateLogin = [
  body("email").trim().isEmail().normalizeEmail(),
  body("password").notEmpty().withMessage("Password is required."),
];

// -----------------------------------------------------------------------------
// 3f. Middleware to return validation errors if any exist
// -----------------------------------------------------------------------------
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
}

module.exports = {
  helmetMiddleware,
  loginRateLimiter,
  generalRateLimiter,
  validateRegister,
  validateLogin,
  handleValidationErrors,
};
