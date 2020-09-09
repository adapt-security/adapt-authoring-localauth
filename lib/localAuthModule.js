const { AbstractAuthModule, AuthError, AuthToken } = require('adapt-authoring-auth');
const _ = require('lodash');
const moment = require('moment');

const PasswordUtils = require('./passwordUtils');
/**
* Module which implements username/password (local) authentication
* @extends {AbstractModule}
*/
class LocalAuthModule extends AbstractAuthModule {
  static formatRemainingTime(secs) {
    return secs < 60 ? `${secs} seconds` : moment().add(secs, 'seconds').fromNow();
  }
  /** @override */
  async setValues() {
    this.type = 'local';
    this.routes = [
      {
        route: '/register',
        handlers: { post: this.registerHandler.bind(this) }
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

    this.unsecureRoute(`/register`, 'post');
    this.unsecureRoute(`/forgotpass`, 'post');
    this.unsecureRoute(`/changepass`, 'post');
    
    const [server, users] = await this.app.waitForModule('server', 'users');
    
    this.users = users;
    server.api.addMiddleware(this.processSessionMiddleware);
    
    this.setReady();
  }
  /** @override */
  async authenticate(req, res) {
    const { email, password } = req.body;
    if(!email || !password) {
      throw AuthError.Authenticate('Must provide user login details');
    }
    const [user] = await this.users.find({ email });
    if(!user) {
      throw AuthError.Authenticate('invalid login credentials provided');
    }
    await this.checkLocking(user);

    try {
      await PasswordUtils.compare(password, user.password);
      await this.updateUser(user._id, { failedLoginAttempts: 0 });

      req.session.token = await AuthToken.generate('local', user);
      res.json({ token: req.session.token });

    } catch(e) {
      await this.applyLocking(user);
      throw e;
    }
  }
  async checkLocking(user) {
    const tempLockEndTime = new Date(user.lastFailedLoginAttempt).getTime()+this.getConfig('temporaryLockDuration')*1000;
    const tempLockRemainingSecs = Math.round((tempLockEndTime-Date.now())/1000);

    if(user.isPermLocked) {
      throw AuthError.Authenticate('account is permanently locked, please contact an administrator for assistance');
    }
    if(user.isTempLocked) {
      if(tempLockRemainingSecs > 0) {
        throw AuthError.Authenticate(`account is temporarily locked, please try again in ${LocalAuthModule.formatRemainingTime(tempLockRemainingSecs)}`);
      }
      await this.updateUser(user._id, { isTempLocked: false });
    }
  }
  async applyLocking(user) {
    const failedLoginAttempts = user.failedLoginAttempts+1;
    const isTempLocked = failedLoginAttempts % this.getConfig('failsUntilTemporaryLock') === 0;
    const isPermLocked = failedLoginAttempts >= this.getConfig('failsUntilPermanentLock');
    const lastFailedLoginAttempt = new Date().toISOString();
    let errorMsg;

    if(isPermLocked) {
      errorMsg = 'account has been permanently locked due to too many invalid login attempts';
    } else if(isTempLocked) {
      errorMsg = 'account has been temporarily locked due to too many invalid login attempts';
    } else {
      errorMsg = 'invalid login credentials provided';
    }
    await this.updateUser(user._id, {
      failedLoginAttempts,
      isTempLocked,
      isPermLocked,
      lastFailedLoginAttempt
    });
    this.log('warn', `failed login attempt recorded for ${user.email}`);
    throw AuthError.Authenticate(errorMsg);
  }
  /**
  * Registers a new user
  * @param {Object} data Data to be used for doc creation
  * @return {Promise} Resolves with the new user's data
  */
  async register(data) {
    const auth = await this.app.waitForModule('auth');
    const userData = await this.validate({
      ...data,
      password: await PasswordUtils.generate(data.password)
    });
    return auth.findOrCreateUser('local', data.email, userData);
  }
  /**
  * Updates a single user
  * @param {String|ObjectId|Object} userIdOrQuery Accepts a user _id or a query object
  * @param {Object} updateData JSON data to use for update
  * @return {Promise}
  */
  async updateUser(userIdOrQuery, updateData) {
    const isId = _.isString(userIdOrQuery) || userIdOrQuery.constructor && userIdOrQuery.constructor.name === 'ObjectID';
    const user = await this.users.update(isId ? { _id: userIdOrQuery } : userIdOrQuery, await this.validate(updateData));
    if(updateData.password) {
      const text = `Someone (hopefully you) has updated the password for your Adapt account. If you suspect foul play, please contact your site admin ASAP.`;
      const html = `<h2>You've got a new password</h2><p>Someone (hopefully you) has updated the password for your Adapt account.</p><p>If you suspect foul play, please contact your site admin ASAP.</p>`;
      await mailer.send(user.email, 'Your Adapt password has been updated', text, html);
    }
    return user;
  }
  /**
  * Validates user data against the schema
  * @param {Object} dataToValidate JSON data to be validated
  * @return {Promise}
  */
  async validate(dataToValidate) {
    const jsonschema = await this.app.waitForModule('jsonschema');
    return jsonschema.validate('localauthuser', dataToValidate, { ignoreRequired: true });
  }
  /**
  * Handles sending a user password reset
  * @param {ClientRequest} req
  * @param {ServerResponse} res
  * @param {Function} next
  */
  async forgotPasswordHandler(req, res, next) {
    const { email } = req.body;
    if(!email) {
      return res.sendError(res.StatusCodes.Error.User, 'Must provide an email address');
    }
    try {
      const mailer = await this.app.waitForModule('mailer');
      const token = await PasswordUtils.createReset(req.body.email);
      const url = `${this.router.url}/reset?token=${token}&email=${req.body.email}`;
      const text = `We heard you were having trouble getting into your Adapt account.\n\nPlease visit the following link in your web browser to reset your password:\n${url}`;
      const html = `<h2>Forgotten your keys?</h2><p>We heard you were having trouble getting into your Adapt account. You can use the link below to reset your password:</p><p><a href="${url}">${url}</a></p><p>If you didn't request to change your password, you can safely ignore this email and the link will expire shortly.</p>`;
      await mailer.send(req.body.email, 'Reset your Adapt password', text, html);
    } catch(e) { // don't want errors to be sent back to user
      this.log('error', `Failed to create user password reset, ${e}`);
    }
    res.status(res.StatusCodes.Success.Default).json({
      error: 'If an account is found matching the details provided, you will be emailed with instructions for resetting your password.'
    });
  }
  /**
  * Handles user registration requests
  * @param {ClientRequest} req
  * @param {ServerResponse} res
  * @param {Function} next
  */
  async registerHandler(req, res, next) {
    try {
      res.json(await this.register(req.body));
    } catch(e) {
      res.sendError(res.StatusCodes.Error.User, `cannot register user, ${e.message}`);
    }
  }
  /**
  * Handles changing a user password
  * @param {ClientRequest} req
  * @param {ServerResponse} res
  * @param {Function} next
  */
  async changePasswordHandler(req, res, next) {
    try {
      if(req.auth.token.authType !== this.type) {
        const e = new Error(`Cannot disavow, you are not authenticated with ${this.type} authentication`);
        e.statusCode = res.StatusCodes.Error.User; 
        throw e;
      }
      const email = req.auth ? req.body.email : req.auth.user.email;
      const token = req.body.token;

      await PasswordUtils.validateReset(email, token);
      await PasswordUtils.deleteReset(token);
      
      const { _id } = await this.updateUser({ email }, { password: await PasswordUtils.generate(req.body.password) });
      await this.disavow(_id);
    } catch(e) {
      res.sendError(res.StatusCodes.Error.User, e);
    }
    res.status(res.StatusCodes.Success.NoContent).end();
  }
  processSessionMiddleware(req, res, next) {
    const token = req.session && req.session.token;
    if(token && !req.headers.Authorization) {
      req.headers.Authorization = `Bearer ${token}`;
    }
    next();
  }
}

module.exports = LocalAuthModule;
