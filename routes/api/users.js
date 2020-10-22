const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator/check');
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const User = require('../../models/User');

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
  async (req, res) => {
    // If there are errors, send 400 bad request and a list of errors using errors.array() function
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;
    try {
      // Check if user exists
      let user = await User.findOne({ email });
      // Warn if user already exists
      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'User with this email already exists' }] });
      }

      // Get users gravatar (based on email)
      const avatar = gravatar.url(email, {
        s: '200', // size
        r: 'pg', // rating (prevent or allow explicit content)
        d: 'mm', // default - mm gives back a default img
      });

      // Create user
      user = new User({
        name,
        email,
        avatar,
        password,
      });

      //  Encrypt password - using bcrypt

      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);

      // save user to DB
      await user.save();

      // Return JWT
      res.send('User registered successfully');
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

module.exports = router;
