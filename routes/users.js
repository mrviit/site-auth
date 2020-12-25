//#routes/users.js
 
const express = require('express');
const router = express.Router()
const Joi = require('joi')
const passport = require('passport')
const { check, validationResult} = require("express-validator/check");
const jwt = require("jsonwebtoken");
 
const User = require('../models/user')
 
 
//validation schema
 
const userSchema = Joi.object().keys({
  email: Joi.string().email().required(),
  username: Joi.string().required(),
  password: Joi.string().regex(/^[a-zA-Z0-9]{6,30}$/).required(),
  confirmationPassword: Joi.any().valid(Joi.ref('password')).required()
})
 
router.route('/register')
  .get((req, res) => {
    res.render('register')
  })
  .post(async (req, res, next) => {
    try {
      const result = Joi.validate(req.body, userSchema)
      if (result.error) {
        req.flash('error', 'Data entered is not valid. Please try again.')
        res.redirect('/users/register')
        return
      }
 
      const user = await User.findOne({ 'email': result.value.email })
      if (user) {
        req.flash('error', 'Email is already in use.')
        res.redirect('/users/register')
        return
      }
 
      const hash = await User.hashPassword(result.value.password)
 
      delete result.value.confirmationPassword
      // result.value.password = hash
 
      const newUser = await new User(result.value)
      await newUser.save()
 
      req.flash('success', 'Registration successfully, go ahead and login.')
      res.redirect('/users/login')
 
    } catch(error) {
      next(error)
    }
  })
 
  router.route('/login')
  .get((req, res) => {
    res.render('login')
  })

  router.route('/statistical')
  .get((req, res) => {
    res.render('statistical')
  })

///
router.post(
  "/signup",
  [
      check("username", "Please Enter a Valid Username")
      .not()
      .isEmpty(),
      check("email", "Please enter a valid email").isEmail(),
      check("password", "Please enter a valid password").isLength({
          min: 6
      })
  ],
  async (req, res) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
          return res.status(400).json({
              errors: errors.array()
          });
      }

      const {
          username,
          email,
          password
      } = req.body;
      try {
          let user = await User.findOne({
              email
          });
          if (user) {
              return res.status(400).json({
                  msg: "User Already Exists"
              });
          }

          user = new User({
              username,
              email,
              password
          });

          const salt = await bcrypt.genSalt(10);
          user.password = await bcrypt.hash(password, salt);

          await user.save();

          const payload = {
              user: {
                  id: user.id
              }
          };

          jwt.sign(
              payload,
              "randomString", {
                  expiresIn: 10000
              },
              (err, token) => {
                  if (err) throw err;
                  res.status(200).json({
                      token
                  });
              }
          );
      } catch (err) {
          console.log(err.message);
          res.status(500).send("Error in Saving");
      }
  }
);
///


  module.exports = router
