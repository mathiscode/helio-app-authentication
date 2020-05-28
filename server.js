/*
* Helio User Authentication App
*/

const Package = require('./package.json')

const path = require('path')
const jwt = require('jsonwebtoken')
const passport = require('passport')
const mailgun = require('mailgun-js')

// Setup Mailgun API if applicable
let Mailgun

if (process.env.MAILGUN_API_KEY) {
  Mailgun = mailgun({ apiKey: process.env.MAILGUN_API_KEY, domain: process.env.MAILGUN_DOMAIN })
}

// Setup Passport strategies
const Strategies = {
  local: require('passport-local').Strategy,
  jwt: require('passport-jwt').Strategy,
  google: require('passport-google-oauth20').Strategy
}

const ExtractJwt = require('passport-jwt').ExtractJwt

module.exports = class {
  constructor (router, logger, mongoose, options) {
    this.options = typeof options === 'object' ? options : {}
    this.package = Package
    this.router = router
    this.log = logger
    this.mongoose = mongoose

    this.name = this.options.name || 'Helio User System'
    this.root = this.options.root || '/apps/auth'

    // Setup CORS Allowed Origins
    this.corsAllowedOrigins = ['http://localhost:3000']

    // Load models
    this.models = {
      User: require('./models/User')(this.mongoose)
    }

    // Clear all users; for development
    // this.models.User.deleteMany({}).exec()

    // Setup authentication strategies
    this.router.use(passport.initialize())

    passport.use(new Strategies.jwt({
      secretOrKey: process.env.JWT_SECRET,
      jwtFromRequest: req => {
        var token = null;
        if (req && req.headers && req.headers.authorization) token = req.headers.authorization.split(' ')[1]
        return token
      }
    }, async (payload, done) => {
      if (payload && payload.data) {
        const user = await this.models.User.findOne({ uuid: payload.data.uuid }).select('-__v -_id -password')
        if (!user.flags.confirmed) return done(null, false, { message: 'You have not confirmed your email address' })
        return done(null, user)
      }

      return done(null, false)
    }))

    if (process.env.GOOGLE_OAUTH_CLIENT_ID) {
      passport.use(new Strategies.google({
        clientID: process.env.GOOGLE_OAUTH_CLIENT_ID,
        clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_OAUTH_CALLBACK_URL
      }, (accessToken, refreshToken, profile, done) => {
        // console.log({ accessToken, refreshToken, profile })
        return done(null, profile)
      }))

      // Handle Google oauth callback
      this.router.get('/callback/google', passport.authenticate('google'), async (req, res, next) => {
        const googleProfile = req.user
        const existingUser = await this.models.User.findOne({ 'email': googleProfile.emails[0].value })

        if (!existingUser) {
          const newUser = await this.createUser({
            username: googleProfile.emails[0].value,
            email: googleProfile.emails[0].value,
            password: (Date.now() * Math.random()).toString(36),
            roles: ['user', 'socially-authenticated'],
            flags: { confirmed: googleProfile.emails[0].verified },
            socialAccounts: {
              google: {
                id: googleProfile.id,
                data: googleProfile
              }
            },
            profile: {
              name: googleProfile.displayName,
              photo: googleProfile.photos[0].value
            }
          })

          req.user = { uuid: newUser.uuid }
          this.log.info('Helio User System', { 'Google Registered': { uuid: newUser.uuid, username: newUser.username } })
        } else {
          req.user = { uuid: existingUser.uuid }
          this.log.info('Helio User System', { 'Google Authenticated': { uuid: existingUser.uuid, username: existingUser.username } })
          this.models.User
            .findOneAndUpdate(
              { uuid: req.user.uuid }, 
              {
                'socialAccounts.google': {
                  id: googleProfile.id,
                  data: googleProfile
                }
              }
            ).exec()
        }

        this.login(req, res, next)
      })
    }

    passport.use(new Strategies.local(async (username, password, done) => {
      try {
        const user = await this.models.User.findOne({ username })
        if (!user) return done(null, false, { message: 'Incorrect username or password' })
        if (!user.validPassword(password)) return done(null, false, { message: 'Incorrect username or password' })
        return done(null, { uuid: user.uuid })
      } catch (err) {
        return done(err)
      }
    }))

    passport.serializeUser((user, done) => { done(null, JSON.stringify(user)) })
    passport.deserializeUser((obj, done) => { done(null, JSON.parse(obj)) })

    // Setup the app's routes
    this.router.get('/create-local-admin', this.createLocalAdmin.bind(this))
    this.router.get('/whoami', passport.authenticate('jwt'), this.whoami.bind(this))
    this.router.get('/refresh-token', passport.authenticate('jwt'), this.refreshToken.bind(this))
    this.router.post('/reset-password', this.getResetPasswordToken.bind(this))
    this.router.post('/reset-password/finalize', this.resetPassword.bind(this))

    // Setup authentication routes
    this.router.post('/login', passport.authenticate('local', { session: false }), this.login.bind(this)) // Handle plain username/password POST login
    this.router.post('/signup', this.signup.bind(this))

    if (process.env.GOOGLE_OAUTH_CLIENT_ID)
      this.router.get('/social/google', passport.authenticate('google', { scope: ['profile', 'email'] }), this.login.bind(this)) // Handle Google oauth
  }

  // Will allow creation of the initial local admin account as long as there are no existing user records
  async createLocalAdmin (req, res, next) {
    const userCount = await this.models.User.countDocuments({})
    if (userCount !== 0) return res.status(403).end()

    const password = (Date.now() * Math.random()).toString(36)

    const user = await this.createUser({
      username: 'admin',
      email: process.env.ADMIN_EMAIL || 'helioblackhole@mailinator.com',
      password: password,
      roles: ['admin'],
      flags: { confirmed: true }
    }, false)

    const token = await this.authorizeUser({ uuid: user.uuid })
    res.send(token)
  }

  whoami (req, res, next) {
    res.json(req.user)
  }

  async createUser (userData, log = true) {
    const { password } = userData
    userData.password = this.models.User.hashPassword(password)
    const user = new this.models.User(userData)
    await user.save()

    if (log) this.log.warn('Helio User System', { 'New User': {
      uuid: user.uuid,
      username: user.username,
      createdAt: user.createdAt,
      roles: user.roles
    }})

    return user
  }

  async authorizeUser (userData) {
    const token = jwt.sign({
      data: userData
    }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_TIMEOUT || '1h' })

    return token
  }

  refreshToken (req, res, next) {
    if (!req.user || !req.user.uuid) return res.status(403).end()
    req.user = { uuid: req.user.uuid }
    this.login(req, res, next)
  }

  async signup (req, res, next) {
    
  }

  async login (req, res, next) {
    // Generate user token and send to client
    if (!req.user) return res.status(403).end()
    const token = await this.authorizeUser(req.user)
    res.send(token)
  }

  async getResetPasswordToken (req, res, next) {
    const { email } = req.body
    if (!email) return res.status(400).end('You must include an email property')

    const user = await this.models.User.findOne({ email }).select('email tokens')
    user.generateResetPasswordToken()

    if (process.env.MAILGUN_API_KEY) {
      Mailgun.messages().send({
        from: process.env.MAILGUN_FROM_ADDRESS,
        to: user.email,
        subject: 'Your password reset token',
        text: `Your password reset token: ${user.tokens.resetPassword}`
      }, (err, body) => {
        if (err) throw err
        this.log.verbose(this.name, { 'Reset Token sent to': user.email, emailId: body.id })
        res.end(`Token sent to ${user.email}`)
      })
    } else {
      res.status(405).end('Mailgun is not configured; cannot send reset token')
    }
  }

  async resetPassword (req, res, next) {
    const { resetPasswordToken, newPassword } = req.body

    const user = await this.models.User.findOne({ 'tokens.resetPassword': resetPasswordToken })
    if (!user) return res.status(400).end('Invalid reset token')

    if (user.resetPassword(resetPasswordToken, newPassword)) {
      return res.json({ msg: 'Password changed successfully' })
    } else {
      return res.status(400).end('Unable to update password')
    }
  }
}
