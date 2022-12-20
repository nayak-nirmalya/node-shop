const express = require('express')
const { check, body } = require('express-validator')

const authController = require('../controllers/auth')
const User = require('../models/user')

const router = express.Router()

router.get('/login', authController.getLogin)

router.get('/signup', authController.getSignup)

router.post(
  '/login',
  [
    check('email')
      .isEmail()
      .withMessage('Please! Enter a Valid E-Mail.')
      .normalizeEmail(),
    body(
      'password',
      'Please enter a password with only numbers and text with at least 5 characters.',
    )
      .isLength({ min: 5 })
      .isAlphanumeric()
      .trim(),
  ],
  authController.postLogin,
)

router.post(
  '/signup',
  [
    check('email')
      .isEmail()
      .withMessage('Please! Enter a Valid E-Mail.')
      .custom((value, { req }) => {
        // if (value === 'test@test.com') {
        //   throw new Error('This E-Mail is Forbidden!')
        // } else {
        //   return true
        return User.findOne({ email: value }).then((userDoc) => {
          if (userDoc) {
            return Promise.reject('E-Mail Already Exists!')
          }
        })
      })
      .normalizeEmail(),
    body(
      'password',
      'Please enter a password with only numbers and text with at least 5 characters.',
    )
      .isLength({ min: 5 })
      .isAlphanumeric()
      .trim(),
    body('confirmPassword')
      .custom((value, { req }) => {
        if (value !== req.body.password) {
          throw new Error('Password have to match!')
        }
        return true
      })
      .trim(),
  ],
  authController.postSignup,
)

router.post('/logout', authController.postLogout)

router.get('/reset', authController.getReset)

router.post('/reset', authController.postReset)

router.get('/reset/:token', authController.getNewPassword)

router.post('/new-password', authController.postNewPassword)

module.exports = router
