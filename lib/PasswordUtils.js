import { App } from 'adapt-authoring-core'
import bcrypt from 'bcryptjs'
import crypto from 'crypto'
import { promisify } from 'util'

/** @ignore */ const passwordResetsCollectionName = 'passwordresets'
/**
 * Various utilities related to password functionality
 * @memberof localauth
 */
class PasswordUtils {
  /**
   * Retrieves a localauth config item
   * @return {Promise}
   */
  static async getConfig (...keys) {
    const authlocal = await App.instance.waitForModule('auth-local')

    if (keys.length === 1) {
      return authlocal.getConfig(keys[0])
    }
    return keys.reduce((m, k) => {
      m[k] = authlocal.getConfig(k)
      return m
    }, {})
  }

  /**
   * Compares a plain password to a hash
   * @param {String} plainPassword
   * @param {String} hash
   * @return {Promise}
   */
  static async compare (plainPassword, hash) {
    const error = App.instance.errors.INVALID_LOGIN_DETAILS
    if (!plainPassword || !hash) {
      throw error.setData({
        error: App.instance.errors.INVALID_PARAMS.setData({ params: ['plainPassword', 'hash'] })
      })
    }
    try {
      const isValid = await promisify(bcrypt.compare)(plainPassword, hash)
      if (!isValid) throw new Error()
    } catch (e) {
      throw error.setData({ error: App.instance.errors.INCORRECT_PASSWORD })
    }
  }

  /**
   * Validates a password against the stored config settings
   * @param {String} password Password to validate
   * @returns {Promise} Resolves if the password passes the validation
   */
  static async validate (password) {
    const authlocal = await App.instance.waitForModule('auth-local')
    if (typeof password !== 'string') {
      throw App.instance.errors.INVALID_PARAMS.setData({ params: ['password'] })
    }
    const match = (key, re) => !authlocal.getConfig(key) || password.search(re) > -1
    const validationChecks = {
      INVALID_PASSWORD_LENGTH: [password.length >= authlocal.getConfig('minPasswordLength'), { length: localauth.getConfig('minPasswordLength') }],
      INVALID_PASSWORD_NUMBER: [match('passwordMustHaveNumber', /[0-9]/)],
      INVALID_PASSWORD_UPPERCASE: [match('passwordMustHaveUppercase', /[A-Z]/)],
      INVALID_PASSWORD_LOWERCASE: [match('passwordMustHaveLowercase', /[a-z]/)],
      INVALID_PASSWORD_SPECIAL: [match('passwordMustHaveSpecial', /[#?!@$%^&*-]/)]
    }
    const errors = Object.entries(validationChecks).reduce((m, [code, [isValid, data]]) => {
      if (!isValid) m.push(App.instance.errors[code].setData(data))
      return m
    }, [])
    if (errors.length) throw App.instance.errors.INVALID_PASSWORD.setData({ errors })
  }

  /**
   * Generates a secure hash from a plain-text password
   * @param {String} plainPassword
   * @return {Promise} Resolves with the hash
   */
  static async generate (plainPassword) {
    if (!plainPassword) {
      throw App.instance.errors.INVALID_PARAMS.setData({ params: ['plainPassword'] })
    }
    const jsonschema = await App.instance.waitForModule('jsonschema')
    const schema = await jsonschema.getSchema('localpassword')
    await schema.validate({ password: plainPassword })

    const saltRounds = await PasswordUtils.getConfig('saltRounds')
    const salt = await promisify(bcrypt.genSalt)(saltRounds)

    return promisify(bcrypt.hash)(plainPassword, salt)
  }

  /**
   * Creates a password reset token
   * @param {String} email The user's email address
   * @param {Number} lifespan The intended token lifespan in milliseconds
   * @return {Promise} Resolves with the token value
   */
  static async createReset (email, lifespan) {
    const [mongodb, users] = await App.instance.waitForModule('mongodb', 'users')
    const [user] = await users.find({ email })
    if (!user) {
      throw App.instance.errors.NOT_FOUND
        .setData({ type: 'user', id: email })
    }
    if (user.authType !== 'local') {
      this.log('error', `Failed to reset ${user._id} password, not authenticated with local auth`)
      throw App.instance.errors.ACCOUNT_NOT_LOCALAUTHD
    }
    // invalidate any previous tokens for this user
    await mongodb.getCollection(passwordResetsCollectionName).deleteMany({ email })

    if (!lifespan) {
      lifespan = await this.getConfig('resetTokenLifespan')
    }
    const { token } = await mongodb.insert(passwordResetsCollectionName, {
      email,
      expiresAt: new Date(Date.now() + lifespan).toISOString(),
      token: await this.getRandomHex()
    })
    return token
  }

  /**
   * Deletes a stored password reset token
   * @param {String} token The token value
   * @return {Promise}
   */
  static async deleteReset (token) {
    const mongodb = await App.instance.waitForModule('mongodb')
    return mongodb.delete(passwordResetsCollectionName, { token })
  }

  /**
   * Creates a random hex string
   * @param {Number} size Size of string
   * @return {Promise} Resolves with the string value
   */
  static async getRandomHex (size = 32) {
    const buffer = await promisify(crypto.randomBytes)(size)
    return buffer.toString('hex')
  }

  /**
   * Validates a password reset token
   * @param {String} token The password reset token
   * @return {Promise} Rejects on invalid token
   */
  static async validateReset (token) {
    if (!token) {
      throw App.instance.errors.INVALID_PARAMS.setData({ params: ['token'] })
    }
    const [mongodb, users] = await App.instance.waitForModule('mongodb', 'users')
    const [tokenData] = await mongodb.find(passwordResetsCollectionName, { token })
    if (!tokenData) {
      throw App.instance.errors.NOT_FOUND
        .setData({ type: 'authtoken' })
    }
    if (new Date(tokenData.expiresAt) < new Date()) {
      throw App.instance.errors.AUTH_TOKEN_EXPIRED
    }
    const [user] = await users.find({ email: tokenData.email })
    if (!user) {
      throw App.instance.errors.NOT_FOUND
        .setData({ type: 'user', id: token.email })
    }
    return tokenData
  }
}

export default PasswordUtils
