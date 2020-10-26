const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const User = require('../../models/User');
const jwt = require('jsonwebtoken');
const config = require('config');

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

      //  Encrypt password - using  bcrypt

      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);

      // save user to DB
      await user.save();

      // Return JWT
      const payload = {
        user: {
          id: user.id, // get the id of the user that got saved
          // in mongoDb user id is "_id", mongoose allows to just write "id"
        },
      };
      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: 360000 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );

      //    res.send('User registered successfully');
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

module.exports = router;
