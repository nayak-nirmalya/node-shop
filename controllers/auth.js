const User = require('../models/user')

exports.getLogin = (req, res, next) => {
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    isAuthenticated: false,
  })
}

exports.getSignup = (req, res, next) => {
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    isAuthenticated: false,
  })
}

exports.postLogin = (req, res, next) => {
  User.findById('639b35a1ac1945d38ce10215')
    .then((user) => {
      req.session.isLoggedIn = true
      req.session.user = user
      req.session.save((err) => {
        console.error(err)
        res.redirect('/')
      })
    })
    .catch((err) => console.log(err))
}

exports.postSignup = (req, res, next) => {
  const { email, password, confirmPassword } = req.body
  User.findOne({ email: email })
    .then((userDoc) => {
      if (userDoc) {
        return res.redirect('/signup')
      }
      const user = new User({
        email: email,
        password: password,
        cart: { items: [] },
      })
      return user.save()
    })
    .then((result) => {
      res.redirect('/login')
    })
    .catch((err) => console.error(err))
}

exports.postLogout = (req, res, next) => {
  req.session.destroy((err) => {
    console.error(err)
    res.redirect('/')
  })
}
