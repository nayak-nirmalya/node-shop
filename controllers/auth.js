const crypto = require('crypto')

const bcrypt = require('bcryptjs')
const nodemailer = require('nodemailer')
const sendgridTransport = require('nodemailer-sendgrid-transport')
const { validationResult } = require('express-validator')

const User = require('../models/user')

const transporter = nodemailer.createTransport(
  sendgridTransport({
    auth: {
      api_key: process.env.SEND_GRID_API_KEY,
    },
  }),
)

exports.getLogin = (req, res, next) => {
  let message = req.flash('error')
  if (message.length > 0) {
    message = message[0]
  } else {
    message = null
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message,
    oldInput: {
      email: '',
      password: '',
    },
    validationErrors: [],
  })
}

exports.getSignup = (req, res, next) => {
  let message = req.flash('error')
  if (message.length > 0) {
    message = message[0]
  } else {
    message = null
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: message,
    oldInput: {
      email: '',
      password: '',
      confirmPassword: '',
    },
    validationErrors: [],
  })
}

exports.postLogin = (req, res, next) => {
  const { email, password } = req.body
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    console.error(errors.array())
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'LogIn',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
      },
      validationErrors: errors.array(),
    })
  }
  User.findOne({
    email: email,
  })
    .then((user) => {
      if (!user) {
        return res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'LogIn',
          errorMessage: 'Invalid E-Mail!',
          oldInput: {
            email: email,
            password: password,
          },
          validationErrors: [],
        })
      }
      bcrypt
        .compare(password, user.password)
        .then((doMatch) => {
          if (doMatch) {
            req.session.isLoggedIn = true
            req.session.user = user
            return req.session.save(() => {
              res.redirect('/')
            })
          }
          return res.status(422).render('auth/login', {
            path: '/login',
            pageTitle: 'LogIn',
            errorMessage: 'Invalid Password!',
            oldInput: {
              email: email,
              password: password,
            },
            validationErrors: [],
          })
        })
        .catch((err) => {
          res.redirect('/login')
        })
    })
    .catch((err) => {
      const error = new Error(err)
      error.httpStatusCode = 500
      return next(error)
    })
}

exports.postSignup = (req, res, next) => {
  const { email, password, confirmPassword } = req.body
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    console.error(errors.array())
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
        confirmPassword: req.body.confirmPassword,
      },
      validationErrors: errors.array(),
    })
  }

  bcrypt
    .hash(password, 12)
    .then((hashedPassword) => {
      const user = new User({
        email: email,
        password: hashedPassword,
        cart: { items: [] },
      })
      return user.save()
    })
    .then((result) => {
      res.redirect('/login')
      return transporter.sendMail({
        to: email,
        from: 'gobindathedog@gmail.com',
        subject: 'Sign Up Successfull!',
        html: '<h1> You Signed Up! </h1>',
      })
    })
    .catch((err) => {
      const error = new Error(err)
      error.httpStatusCode = 500
      return next(error)
    })
}

exports.postLogout = (req, res, next) => {
  req.session.destroy((err) => {
    // console.error(err)
    res.redirect('/')
  })
}

exports.getReset = (req, res, next) => {
  let message = req.flash('error')
  if (message.length > 0) {
    message = message[0]
  } else {
    message = null
  }
  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset Password',
    errorMessage: message,
  })
}

exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.error(err)
      return res.redirect('/reset')
    }
    const token = buffer.toString('hex')
    User.findOne({ email: req.body.email })
      .then((user) => {
        if (!user) {
          req.flash('error', 'No Account with that E-Mail found.')
          return res.redirect('/reset')
        }
        user.resetToken = token
        user.resetTokenExpiration = Date.now() + 3_600_000
        return user.save()
      })
      .then((result) => {
        res.redirect('/')
        transporter.sendMail({
          to: req.body.email,
          from: 'gobindathedog@gmail.com',
          subject: 'Password Reset',
          html: `
            <p>You requested password reset.</p>
            <p>Click this <a herf="http://localhost:3000/reset/${token}>link</a> to set new password.</p>
          `,
        })
      })
      .catch((err) => {
        const error = new Error(err)
        error.httpStatusCode = 500
        return next(error)
      })
  })
}

exports.getNewPassword = (req, res, next) => {
  const { token } = req.params
  User.findOne({
    resetToken: token,
    resetTokenExpiration: {
      $gt: Date.now(),
    },
  })
    .then((user) => {
      let message = req.flash('error')
      if (message.length > 0) {
        message = message[0]
      } else {
        message = null
      }
      res.render('auth/new-password', {
        path: '/new-password',
        pageTitle: 'New Password',
        errorMessage: message,
        userId: user._id.toString(),
        passwordToken: token,
      })
    })
    .catch((err) => {
      const error = new Error(err)
      error.httpStatusCode = 500
      return next(error)
    })
}

exports.postNewPassword = (req, res, next) => {
  const { password, userId, passwordToken } = req.body
  let resetUser

  User.findOne({
    resetToken: passwordToken,
    resetTokenExpiration: {
      $gt: Date.now(),
    },
    _id: userId,
  })
    .then((user) => {
      resetUser = user
      return bcrypt.hash(password, 12)
    })
    .then((hashedPassword) => {
      resetUser.password = hashedPassword
      resetUser.resetToken = undefined
      resetUser.resetTokenExpiration = undefined
      return resetUser.save()
    })
    .then((result) => {
      res.redirect('/login')
    })
    .catch((err) => {
      const error = new Error(err)
      error.httpStatusCode = 500
      return next(error)
    })
}
