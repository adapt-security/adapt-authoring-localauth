import _ from 'lodash'
import { AbstractAuthModule } from 'adapt-authoring-auth'
import apidefs from './apidefs.js'
import { formatDistanceToNowStrict as toNow } from 'date-fns'
import PasswordUtils from './PasswordUtils.js'
/**
 * Module which implements username/password (local) authentication
 * @memberof localauth
 * @extends {AbstractAuthModule}
 */
class LocalAuthModule extends AbstractAuthModule {
  /**
   * Returns a human-readable string to denote how many seconds are remaining
   * @param {Number} secs The remaining seconds
   */
  static formatRemainingTime (secs) {
    return toNow(Date.now() + (secs * 1000))
  }

  /** @override */
  async setValues () {
    /** @ignore */ this.userSchema = 'localauthuser'
    /** @ignore */ this.type = 'local'
    /** @ignore */ this.routes = [
      {
        route: '/invite',
        handlers: { post: this.inviteHandler.bind(this) },
        meta: apidefs.invite
      }, {
        route: '/registersuper',
        internal: true,
        handlers: { post: this.registerSuperHandler.bind(this) },
        meta: apidefs.registersuper
      }, {
        route: '/changepass',
        handlers: { post: this.changePasswordHandler.bind(this) },
        meta: apidefs.changepass
      }, {
        route: '/forgotpass',
        handlers: { post: this.forgotPasswordHandler.bind(this) },
        meta: apidefs.forgotpass
      }, {
        route: '/validatepass',
        handlers: { post: this.validatePasswordHandler.bind(this) },
        meta: apidefs.validatepass
      }
    ]
  }

  /** @override */
  async init () {
    await super.init()
    this.secureRoute('/invite', 'post', ['register:users'])
    this.secureRoute('/validatepass', 'post', ['read:me'])
    this.unsecureRoute('/registersuper', 'post')
    this.unsecureRoute('/changepass', 'post')
    this.unsecureRoute('/forgotpass', 'post')
    // add API metadata
    this.router.routes.find(r => r.route === '/').meta = apidefs.root
    this.router.routes.find(r => r.route === '/register').meta = apidefs.register

    const users = await this.app.waitForModule('users')
    /**
     * Local reference to the current UsersModule instance for convenience
     * @type {UsersModule}
     */
    this.users = users

    this.app.onReady().then(async () => {
      const email = this.getConfig('initialSuperUserEmail')
      if(email) {
        try {
          const password = await PasswordUtils.getRandomHex(this.getConfig('minPasswordLength'))
          await this.registerSuper({ email, password })
          const hrStr = ''.padEnd(80, '=')
          console.log([hrStr, email, password, hrStr].join('\n'));
        } catch(e) {
          if (e.code !== this.app.errors.SUPER_USER_EXISTS.code) {
            throw e
          }
        }
      }
    })
  }

  /** @override */
  async authenticate (user, req, res) {
    if (!req.body.password) {
      throw this.app.errors.INVALID_LOGIN_DETAILS
    }
    const isTempLockTimeout = user.isTempLocked && (new Date(user.lastFailedLoginAttempt).getTime() + this.getConfig('temporaryLockDuration') - Date.now()) > 0
    let failedLoginAttempts = user.failedLoginAttempts
    let lastFailedLoginAttempt
    let error
    try {
      await PasswordUtils.compare(req.body.password, user.password)
    } catch (e) {
      if (!user.isPermLocked && !isTempLockTimeout) { // only update failed login data when account isn't locked
        failedLoginAttempts += 1
        lastFailedLoginAttempt = new Date().toISOString()
      }
      error = e
    }
    const isPermLocked = user.isPermLocked || failedLoginAttempts >= this.getConfig('failsUntilPermanentLock')
    const isTempLocked = isTempLockTimeout || (failedLoginAttempts > 0 && (failedLoginAttempts % this.getConfig('failsUntilTemporaryLock') === 0))

    if (!error && !isPermLocked && !isTempLocked) {
      failedLoginAttempts = 0
    }
    if (user) {
      await this.updateUser(user._id, { isPermLocked, isTempLocked, lastFailedLoginAttempt, failedLoginAttempts })
    }
    if (isPermLocked) throw this.app.errors.ACCOUNT_LOCKED_PERM
    if (isTempLocked) throw this.app.errors.ACCOUNT_LOCKED_TEMP
    if (error) throw error
  }

  /**
   * Checks if the user account is currently locked, and unlocks a temporarily locked account if appropriate
   * @param {external:ExpressRequest} req
   * @param {Object} user The current user
   */
  async handleLockStatus (user) {
    const tempLockEndTime = new Date(user.lastFailedLoginAttempt).getTime() + this.getConfig('temporaryLockDuration') * 1000
    const tempLockRemainingSecs = Math.round((tempLockEndTime - Date.now()) / 1000)

    if (user.isPermLocked) {
      throw this.app.errors.ACCOUNT_LOCKED_PERM
    }
    if (user.isTempLocked) {
      if (tempLockRemainingSecs > 0) {
        throw this.app.errors.ACCOUNT_LOCKED_TEMP
          .setData({ remaining: LocalAuthModule.formatRemainingTime(tempLockRemainingSecs) })
      }
      await this.updateUser(user._id, { isTempLocked: false })
    }
  }

  /** @override */
  async register (data) {
    await PasswordUtils.validate(data.password)
    return super.register({ ...data, password: await PasswordUtils.generate(data.password) })
  }
  
  
  async registerSuper (data) {
    const [roles, users] = await this.app.waitForModule('roles', 'users')
      const [superRole] = await roles.find({ shortName: 'superuser' })
      const superUsers = await users.find({ roles: [superRole._id] })
      if (superUsers.length) {
        throw this.app.errors.SUPER_USER_EXISTS
      }
      await this.register({
        email: data.email,
        password: data.password,
        firstName: 'Super',
        lastName: 'User',
        roles: [superRole._id.toString()]
      })
  }

  /** @override */
  async setUserEnabled (user, isEnabled) {
    await super.setUserEnabled(user, isEnabled)
    await this.users.update({ _id: user._id }, {
      failedLoginAttempts: isEnabled ? 0 : user.failedAttempts,
      isPermLocked: !isEnabled,
      isTempLocked: !isEnabled
    }, {
      schemaName: this.userSchema
    })
  }

  /**
   * Updates a single user
   * @param {external:ExpressRequest} req
   * @param {String|ObjectId|Object} userIdOrQuery Accepts a user _id or a query object
   * @param {Object} updateData JSON data to use for update
   * @return {Promise}
   */
  async updateUser (userIdOrQuery, updateData) {
    const isId = _.isString(userIdOrQuery) || (userIdOrQuery.constructor && userIdOrQuery.constructor.name === 'ObjectId')
    const query = isId ? { _id: userIdOrQuery } : userIdOrQuery

    if (!updateData.password) {
      return this.users.update(query, updateData, { schemaName: this.userSchema, useDefaults: false, ignoreRequired: true })
    }
    await PasswordUtils.validate(updateData.password)
    updateData.password = await PasswordUtils.generate(updateData.password)
    // password updates required special process
    const [mailer, mongodb] = await this.app.waitForModule('mailer', 'mongodb')
    const user = await mongodb.update(this.users.collectionName, query, { $set: updateData })

    const subject = this.app.lang.translate(undefined, 'app.updateusersubject')
    const text = this.app.lang.translate(undefined, 'app.updateusertext')
    const html = this.app.lang.translate(undefined, 'app.updateuserhtml')
    try {
      await mailer.send({ to: user.email, subject, text, html })
    } catch {} // no need to handle error here

    return user
  }

  /**
   * Creates a new password reset token and sends an email
   * @param {String} email
   * @param {String} subject
   * @param {String} textContent
   * @param {String} htmlContent
   * @param {Number} lifespan The lifespan of the reset
   */
  async createPasswordReset (email, subject, textContent, htmlContent, lifespan) {
    if (!email) {
      throw this.app.errors.INVALID_PARAMS.setData({ params: ['email'] })
    }
    try {
      const [mailer, server] = await this.app.waitForModule('mailer', 'server')
      const token = await PasswordUtils.createReset(email, lifespan)
      const url = `${server.root.url}#user/reset?token=${token}&email=${email}`
      await mailer.send({
        to: email,
        subject,
        text: textContent.replace(/{{url}}/g, url),
        html: htmlContent.replace(/{{url}}/g, url)
      })
    } catch (e) {
      this.log('error', `Failed to create user password reset, ${e}`)
      throw e
    }
  }

  /**
   * Handles inviting a new user to the system
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {Function} next
   */
  async inviteHandler (req, res, next) {
    try {
      const { email } = req.body
      const subject = req.translate('app.invitepasswordsubject')
      const text = req.translate('app.invitepasswordtext')
      const html = req.translate('app.invitepasswordhtml')
      await this.createPasswordReset(email, subject, text, html, this.getConfig('inviteTokenLifespan'))
      this.log('debug', 'INVITE_SENT', email, req?.auth?.user?._id?.toString())
    } catch (e) {
      return next(e)
    }
    res.sendStatus(204)
  }

  /**
   * Registers a Super User. This is restricted to localhost, and can only be used to create the first Super User.
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {Function} next
   */
  async registerSuperHandler (req, res, next) {
    try {
      await this.registerSuper(req.body)
      res.sendStatus(204)
    } catch (e) {
      next(e)
    }
  }

  /**
   * Handles sending a user password reset
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {Function} next
   */
  async forgotPasswordHandler (req, res, next) {
    try {
      const { email } = req.body
      const subject = req.translate('app.forgotpasswordsubject')
      const text = req.translate('app.forgotpasswordtext')
      const html = req.translate('app.forgotpasswordhtml')
      await this.createPasswordReset(email, subject, text, html)
      this.log('debug', 'RESET_SENT', email, req?.auth?.user?._id?.toString())
    } catch (e) { // don't return an error to avoid signifying correct user/pass combinations
      this.log('error', 'RESET_PASS_FAILED', e)
    }
    res.status(200).json({ message: req.translate('app.forgotpasswordmessage') })
  }

  /**
   * Handles changing a user password. If no auth is given, a reset token must be present
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {Function} next
   */
  async changePasswordHandler (req, res, next) {
    let email
    try {
      if (req.auth.token) { // already authenticated, so can use auth data
        if (req.auth.token.type !== this.type) throw new Error()
        // allow for a specific email to be passed via body, falling back to the email from the auth data
        email = req.body.email || req.auth.user.email
      } else { // no authenticated, so should expect body data
        const tokenData = await PasswordUtils.validateReset(req.body.token)
        email = tokenData.email
      }
      if (!email) throw new Error()

      const { _id } = await this.updateUser({ email }, { password: req.body.password })

      if (!req.auth.token) {
        await PasswordUtils.deleteReset(req.body.token)
      }
      await this.disavowUser({ userId: _id, signature: req.auth?.token?.signature })
      this.log('debug', 'CHANGE_PASS', _id, req?.auth?.user?._id?.toString())
      res.status(204).end()
    } catch (e) {
      if (email) this.log('debug', 'CHANGE_PASS_FAILED', email)
      return next(e)
    }
  }

  /**
   * Handles changing a user password. If no auth is given, a reset token must be present
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {Function} next
   */
  async validatePasswordHandler (req, res, next) {
    try {
      await PasswordUtils.validate(req.body.password)
      res.json({ message: req.translate('app.passwordindicatorstrong') })
    } catch (e) {
      e.data.errors = e.data.errors.map(req.translate).join(', ')
      res.sendError(e)
    }
  }
}

export default LocalAuthModule
