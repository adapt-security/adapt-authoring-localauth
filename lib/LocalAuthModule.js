import _ from 'lodash';
import { AbstractAuthModule, AuthToken } from 'adapt-authoring-auth';
import { addSeconds, formatDistanceToNowStrict as toNow } from 'date-fns';
import PasswordUtils from './PasswordUtils.js';
/**
 * Module which implements username/password (local) authentication
 * @extends {AbstractAuthModule}
 */
class LocalAuthModule extends AbstractAuthModule {
  /**
   * Returns a human-readable string to denote how many seconds are remaining
   * @param {Number} secs The remaining seconds
   */
  static formatRemainingTime(secs) {
    return toNow(addSeconds(Date.now(), secs));
  }
  /** @override */
  async setValues() {
    /** @ignore */ this.userSchema = 'localauthuser';
    /** @ignore */ this.type = 'local';
    /** @ignore */ this.routes = [
      {
        route: '/invite',
        handlers: { post: this.inviteHandler.bind(this) }
      }, {
        route: '/changepass',
        handlers: { post: this.changePasswordHandler.bind(this) }
      }, {
        route: '/forgotpass',
        handlers: { post: this.forgotPasswordHandler.bind(this) }
      }, {
        route: '/unlock/:_id',
        handlers: { post: this.unlockHandler.bind(this) }
      }
    ];
  }
  /** @override */
  async init() {
    await super.init();
    this.secureRoute(`/invite`, 'post', ['register:users']);
    this.secureRoute(`/unlock/:_id`, 'post', ['write:users']);
    this.unsecureRoute(`/changepass`, 'post');
    this.unsecureRoute(`/forgotpass`, 'post');

    const [server, users] = await this.app.waitForModule('server', 'users');
    /**
     * Local reference to the current UsersModule instance for convenience
     * @type {UsersModule}
     */
    this.users = users;
    
    server.api.addMiddleware(this.processSessionMiddleware);
    users.updateHook.tap(async (oldData, newData) => { // we don't allow passwords to be set using the user API
      if(newData.password) throw this.app.errors.API_PASSWORD_CHANGE_FORBIDDEN;
    });
  }
  /** @override */
  async authenticate(req, res) {
    const { email, password, persistSession } = req.body;
    if(!email || !password) {
      throw this.app.errors.INVALID_PARAMS;
    }
    const [user] = await this.users.find({ email });
    if(!user) {
      throw this.app.errors.UNAUTHENTICATED;
    }
    await this.handleLockStatus(user);

    try {
      await PasswordUtils.compare(password, user.password);
      await this.updateUser(req, user._id, { failedLoginAttempts: 0 });

      if(persistSession !== true) req.session.cookie.maxAge = null; 
      else this.log('debug', `storing persistent session cookie for ${user._id}`);
      
      req.session.token = await AuthToken.generate('local', user);
      res.json({ token: req.session.token });

    } catch(e) {
      await this.updateUser(req, user._id, {
        failedLoginAttempts: user.failedLoginAttempts+1,
        lastFailedLoginAttempt: new Date().toISOString()
      });
      this.log('warn', `failed login attempt recorded for ${user.email}`);
      throw this.app.errors.UNAUTHENTICATED;
    }
  }
  /**
   * Checks if the user account is currently locked, and unlocks a temporarily locked account if appropriate
   * @param {ClientRequest} req
   * @param {Object} user The current user
   */
  async handleLockStatus(req, user) {
    const tempLockEndTime = new Date(user.lastFailedLoginAttempt).getTime()+this.getConfig('temporaryLockDuration')*1000;
    const tempLockRemainingSecs = Math.round((tempLockEndTime-Date.now())/1000);

    if(user.isPermLocked) {
      throw this.app.errors.ACCOUNT_LOCKED_PERM;
    }
    if(user.isTempLocked) {
      if(tempLockRemainingSecs > 0) {
        throw this.app.errors.ACCOUNT_LOCKED_TEMP
          .setData({ remaining: LocalAuthModule.formatRemainingTime(tempLockRemainingSecs) });
      }
      await this.updateUser(req, user._id, { isTempLocked: false });
    }
  }
  /** @override */
  async register(data) {
    return super.register({ ...data, password: await PasswordUtils.generate(data.password) });
  }
  /**
   * Updates a single user
   * @param {ClientRequest} req
   * @param {String|ObjectId|Object} userIdOrQuery Accepts a user _id or a query object
   * @param {Object} updateData JSON data to use for update
   * @return {Promise}
   */
  async updateUser(req, userIdOrQuery, updateData) {
    const isId = _.isString(userIdOrQuery) || userIdOrQuery.constructor && userIdOrQuery.constructor.name === 'ObjectId';
    const query = isId ? { _id: userIdOrQuery } : userIdOrQuery;

    if(Number.isInteger(updateData.failedLoginAttempts)) { // update lock status if failedLoginAttempts change
      this.applyLocking(updateData);
    }
    if(!updateData.password) {
      return this.users.update(query, updateData, { schemaName: this.userSchema, useDefaults: false, ignoreRequired: true });
    }
    // password updates required special process
    const [mailer, mongodb] = await this.app.waitForModule('mailer', 'mongodb');
    const user = await mongodb.update(this.users.collectionName, query, { $set: updateData });

    const subject = this.app.lang.t('app.updateusersubject');
    const text = this.app.lang.t('app.updateusertext');
    const html = this.app.lang.t('app.updateuserhtml');

    await mailer.send({ to: user.email, subject, text, html });
    return user;
  }
  /**
   * Checks the user's access history and updates the relevant user attributes
   * @param {Object} userData Data being used for update
   */
   applyLocking(userData) {
    const failedAttempts = userData.failedLoginAttempts;
    userData.isTempLocked = failedAttempts > 0 && failedAttempts % this.getConfig('failsUntilTemporaryLock') === 0;
    userData.isPermLocked = failedAttempts >= this.getConfig('failsUntilPermanentLock');
  }
  /**
   * Creates a new password reset token and sends an email
   * @param {String} email
   * @param {String} subject
   * @param {String} textContent
   * @param {String} htmlContent
   */
  async createPasswordReset(email, subject, textContent, htmlContent) {
    if(!email) {
      throw this.app.errors.INVALID_PARAMS;
    }
    try {
      const [mailer, server] = await this.app.waitForModule('mailer', 'server');
      const token = await PasswordUtils.createReset(email);
      const url = `${server.root.url}#user/reset?token=${token}&email=${email}`;
      await mailer.send({
        to: email,
        subject,
        text: textContent.replace(/{{url}}/g, url),
        html: htmlContent.replace(/{{url}}/g, url)
      });
    } catch(e) {
      this.log('error', `Failed to create user password reset, ${e}`);
      throw e;
    }
  }
  /**
   * Handles inviting a new user to the system
   * @param {ClientRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   */
  async inviteHandler(req, res, next) {
    try {
      const { email } = req.body;
      const subject = this.app.lang.t('app.invitepasswordsubject');
      const text = this.app.lang.t('app.invitepasswordtext');
      const html = this.app.lang.t('app.invitepasswordhtml');
      await this.createPasswordReset(email, subject, text, html);
    } catch(e) {
      return next(e);
    }
    res.sendStatus(204);
  }
  /**
   * Handles sending a user password reset
   * @param {ClientRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   */
  async forgotPasswordHandler(req, res, next) {
    try {
      const { email } = req.body;
      const subject = this.app.lang.t('app.forgotpasswordsubject');
      const text = this.app.lang.t('app.forgotpasswordtext');
      const html = this.app.lang.t('app.forgotpasswordhtml');
      await this.createPasswordReset(email, subject, text, html);
    } catch(e) {} // don't return an error to avoid signifying correct user/pass combinations
    res.status(200).json({ message: this.app.lang.translate(req, 'app.forgotpasswordmessage') });
  }
  /**
   * Handles unlocking a user account
   * @param {ClientRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   */
  async unlockHandler(req, res, next) {
    try {
      await this.updateUser(req, req.params._id, { failedLoginAttempts: 0 });
      res.status(204).end();
    } catch(e) {
      this.log('error', `Failed to unlock user account, ${e.message}`);
      return next(this.app.errors.ACCOUNT_UNLOCK_FAILED);
    }
  }
  /**
   * Handles changing a user password. If no auth is given, a reset token must be present
   * @param {ClientRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   */
  async changePasswordHandler(req, res, next) {
    let email;
    try {
      if(req.auth.token) { // already authenticated, so can use auth data
        if(req.auth.token.type !== this.type) throw new Error();
        // allow for a specific email to be passed via body, falling back to the email from the auth data
        email = req.body.email || req.auth.user.email;
      } else { // no authenticated, so should expect body data
        await PasswordUtils.validateReset(req.body.email, req.body.token);
        email = req.body.email;
      }
      if(!email) throw new Error();

      const { _id } = await this.updateUser(req, { email }, { password: await PasswordUtils.generate(req.body.password) });

      if(!req.auth.token) {
        await PasswordUtils.deleteReset(req.body.token);
      }
      await this.disavowUser(_id);
      res.status(204).end();

    } catch(e) {
      if(email) this.log('debug', `failed password change attempt for user '${email}'`);
      return next(e);
    }
  }
  /**
   * Sets the Authorization header if session data is present
   * @param {ClientRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   */
  processSessionMiddleware(req, res, next) {
    const token = req.session && req.session.token;
    if(token && !req.headers.Authorization) {
      req.headers.Authorization = `Bearer ${token}`;
    }
    next();
  }
}

export default LocalAuthModule;