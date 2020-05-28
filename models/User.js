
const bcrypt = require('bcryptjs')
const { v4: uuidv4 } = require('uuid')

module.exports = (mongoose) => {
  const Schema = mongoose.Schema({
    uuid: { type: String, index: true, unique: true, default: uuidv4 },
    username: { type: String, index: true, unique: true },
    email: { type: String, index: true, unique: true },
    password: String,

    socialAccounts: {
      google: {
        id: { type: Number, unique: false },
        data: {}
      }
    },
  
    roles: [String],
  
    flags: {
      confirmed: { type: Boolean, default: false },
      lastLogin: { type: Date, default: Date.now }
    },
  
    profile: {
      name: String,
      photo: String
    },

    tokens: {
      resetPassword: { type: String, default: null }
    },
  
    settings: {},
    clientSettings: {},
    serverSettings: {}
  }, { timestamps: true })
  
  Schema.methods.validPassword = function (password) {
    return bcrypt.compareSync(password, this.password)
  }

  Schema.methods.generateResetPasswordToken = function () {
    this.tokens.resetPassword = uuidv4()
    this.save()
    return this.tokens.resetPassword
  }

  Schema.methods.resetPassword = function (resetPasswordToken, newPassword) {
    if (!this.tokens.resetPassword) return false
    if (resetPasswordToken === this.tokens.resetPassword) {
      this.tokens.resetPassword = null
      this.password = this.constructor.hashPassword(newPassword)
      this.save()
      return true
    }
  }

  Schema.statics.hashPassword = function (password) {
    return bcrypt.hashSync(password)
  }

  return mongoose.model('User', Schema)
}
