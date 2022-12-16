const bcrypt = require('bcryptjs')
const nodemailer = require('nodemailer')
const sendgridTransport = require('nodemailer-sendgrid-transport')

const User = require('../models/user')

const transporter = nodemailer.createTransport(
  sendgridTransport({
    auth: {
      api_key:
        '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',
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
  })
}

exports.postLogin = (req, res, next) => {
  const { email, password } = req.body
  User.findOne({
    email: email,
  })
    .then((user) => {
      if (!user) {
        req.flash('error', 'Invalid E-Mail or Password!')
        return res.redirect('/login')
      }
      bcrypt
        .compare(password, user.password)
        .then((doMatch) => {
          if (doMatch) {
            req.session.isLoggedIn = true
            req.session.user = user
            return req.session.save((err) => {
              console.error(err)
              res.redirect('/')
            })
          }
          req.flash('error', 'Invalid E-Mail or Password!')
          res.redirect('/login')
        })
        .catch((err) => {
          console.error(err)
          res.redirect('/login')
        })
    })
    .catch((err) => console.log(err))
}

exports.postSignup = (req, res, next) => {
  const { email, password, confirmPassword } = req.body
  User.findOne({ email: email })
    .then((userDoc) => {
      if (userDoc) {
        req.flash('error', 'E-Mail Already Exists!')
        return res.redirect('/signup')
      }
      return bcrypt
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
        .catch((err) => console.error(err))
    })

    .catch((err) => console.error(err))
}

exports.postLogout = (req, res, next) => {
  req.session.destroy((err) => {
    console.error(err)
    res.redirect('/')
  })
}
