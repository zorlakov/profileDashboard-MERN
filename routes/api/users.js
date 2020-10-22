const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator/check');

// @route POST api/users
// @desc Register user
// @access Public
router.post(
  '/',
  // Validate data using express validators
  [check('name', 'Name is required').not().isEmpty()],
  [check('email', 'Please enter a valid email').isEmail()],
  [
    check(
      'password',
      'Please enter a password with 6 or more characters'
    ).isLength({ min: 6 }),
  ],
  (req, res) => {
    // If there are errors, send 400 bad request and a list of errors using errors.array() function
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    res.send('User route');
  }
);

module.exports = router;
