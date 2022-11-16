import _ from 'lodash';
import { AbstractAuthModule, AuthToken } from 'adapt-authoring-auth';
import { formatDistanceToNowStrict as toNow } from 'date-fns';
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
    return toNow(Date.now() + (secs * 1000));
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

    const users = await this.app.waitForModule('users');
    /**
     * Local reference to the current UsersModule instance for convenience
     * @type {UsersModule}
     */
    this.users = users;
  }
  /** @override */
  async authenticate(user, req, res) {
    if(!req.body.password) {
      throw this.app.errors.INVALID_PARAMS;
    }
    try {
      await this.handleLockStatus(user);
      await PasswordUtils.compare(req.body.password, user.password);
      await this.updateUser(user._id, { failedLoginAttempts: 0 });
    } catch(e) {
      if(user) {
        await this.updateUser(user._id, {
          failedLoginAttempts: user.failedLoginAttempts+1,
          lastFailedLoginAttempt: new Date().toISOString()
        });
        throw e;
      }
    }
  }
  /**
   * Checks if the user account is currently locked, and unlocks a temporarily locked account if appropriate
   * @param {external:express~Request} req
   * @param {Object} user The current user
   */
  async handleLockStatus(user) {
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
      await this.updateUser(user._id, { isTempLocked: false });
    }
  }
  /** @override */
  async register(data) {
    await this.validatePassword(data.password);
    return super.register({ ...data, password: await PasswordUtils.generate(data.password) });
  }
  /** @override */
  async setUserEnabled(user, isEnabled) {
    await super.setUserEnabled(user, isEnabled);
    await this.users.update({ _id: user._id }, {
      failedLoginAttempts: isEnabled ? 0 : user.failedAttempts,
      isPermLocked: !isEnabled,
      isTempLocked: !isEnabled
    });
  }
  async validatePassword(password) {
    if(password.length < this.getConfig('minPasswordLength')) {
      throw this.app.errors.INVALID_PASSWORD_LENGTH;
    }
    if(this.getConfig('passwordMustHaveNumber') && password.search(/[0-9]/)) {
      throw this.app.errors.INVALID_PASSWORD_NUMBER;
    }
    if(this.getConfig('passwordMustHaveUppercase') && password.search(/[A-Z]/)) {
      throw this.app.errors.INVALID_PASSWORD_UPPERCASE;
    }
    if(this.getConfig('passwordMustHaveLowercase') && password.search(/[a-z]/)) {
      throw this.app.errors.INVALID_PASSWORD_LOWERCASE;
    }
    if(this.getConfig('passwordMustHaveSpecial') && password.search(/[#?!@$%^&*-]/)) {
      throw this.app.errors.INVALID_PASSWORD_SPECIAL;
    }
  }
  /**
   * Updates a single user
   * @param {external:express~Request} req
   * @param {String|ObjectId|Object} userIdOrQuery Accepts a user _id or a query object
   * @param {Object} updateData JSON data to use for update
   * @return {Promise}
   */
  async updateUser(userIdOrQuery, updateData) {
    const isId = _.isString(userIdOrQuery) || userIdOrQuery.constructor && userIdOrQuery.constructor.name === 'ObjectId';
    const query = isId ? { _id: userIdOrQuery } : userIdOrQuery;

    if(Number.isInteger(updateData.failedLoginAttempts)) { // update lock status if failedLoginAttempts change
      this.applyLocking(updateData);
    }
    if(!updateData.password) {
      return this.users.update(query, updateData, { schemaName: this.userSchema, useDefaults: false, ignoreRequired: true });
    }
    await this.validatePassword(updateData.password);
    updateData.password = await PasswordUtils.generate(updateData.password);
    // password updates required special process
    const [mailer, mongodb] = await this.app.waitForModule('mailer', 'mongodb');
    const user = await mongodb.update(this.users.collectionName, query, { $set: updateData });

    const subject = this.app.lang.t('app.updateusersubject');
    const text = this.app.lang.t('app.updateusertext');
    const html = this.app.lang.t('app.updateuserhtml');
    try {
      await mailer.send({ to: user.email, subject, text, html });
    } catch {} // no need to handle error here

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
   * @param {Number} lifespan The lifespan of the reset
   */
  async createPasswordReset(email, subject, textContent, htmlContent, lifespan) {
    if(!email) {
      throw this.app.errors.INVALID_PARAMS;
    }
    try {
      const [mailer, server] = await this.app.waitForModule('mailer', 'server');
      const token = await PasswordUtils.createReset(email, lifespan);
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
   * @param {external:express~Request} req
   * @param {external:express~Response} res
   * @param {Function} next
   */
  async inviteHandler(req, res, next) {
    try {
      const { email } = req.body;
      const subject = this.app.lang.t('app.invitepasswordsubject');
      const text = this.app.lang.t('app.invitepasswordtext');
      const html = this.app.lang.t('app.invitepasswordhtml');
      await this.createPasswordReset(email, subject, text, html, this.getConfig('inviteTokenLifespan'));
      this.log('debug', 'INVITE_SENT', email, req?.auth?.user?._id?.toString());
    } catch(e) {
      return next(e);
    }
    res.sendStatus(204);
  }
  /**
   * Handles sending a user password reset
   * @param {external:express~Request} req
   * @param {external:express~Response} res
   * @param {Function} next
   */
  async forgotPasswordHandler(req, res, next) {
    try {
      const { email } = req.body;
      const subject = this.app.lang.t('app.forgotpasswordsubject');
      const text = this.app.lang.t('app.forgotpasswordtext');
      const html = this.app.lang.t('app.forgotpasswordhtml');
      await this.createPasswordReset(email, subject, text, html);
      this.log('debug', 'RESET_SENT', email, req?.auth?.user?._id?.toString());
    } catch(e) {} // don't return an error to avoid signifying correct user/pass combinations
    res.status(200).json({ message: this.app.lang.translate(req, 'app.forgotpasswordmessage') });
  }
  /**
   * Handles changing a user password. If no auth is given, a reset token must be present
   * @param {external:express~Request} req
   * @param {external:express~Response} res
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
        const tokenData = await PasswordUtils.validateReset(req.body.token);
        email = tokenData.email;
      }
      if(!email) throw new Error();

      const { _id } = await this.updateUser({ email }, { password: req.body.password });

      if(!req.auth.token) {
        await PasswordUtils.deleteReset(req.body.token);
      }
      await this.disavowUser({ userId: _id, signature: req.auth?.token?.signature });
      this.log('debug', 'CHANGE_PASS', _id, req?.auth?.user?._id?.toString());
      res.status(204).end();

    } catch(e) {
      if(email) this.log('debug', 'CHANGE_PASS_FAILED', email);
      return next(e);
    }
  }
}

export default LocalAuthModule;