const { AbstractModule } = require('adapt-authoring-core');
const { AuthError, AuthToken } = require('adapt-authoring-auth');
const _ = require('lodash');
const moment = require('moment');

const PasswordUtils = require('./passwordUtils');
/**
* Module which implements username/password (local) authentication
* @extends {AbstractModule}
*/
class LocalAuthModule extends AbstractModule {
  static formatRemainingTime(secs) {
    return secs < 60 ? `${secs} seconds` : moment().add(secs, 'seconds').fromNow();
  }
  /** @override */
  constructor(...args) {
    super(...args);
    this.init();
  }
  /**
  * Initialises the module
  * @return {Promise}
  */
  async init() {
    const [ auth, server, users ] = await this.app.waitForModule('auth', 'server', 'users');

    auth.authentication.registerPlugin('local', this);

    this.users = users;
    /**
    * Reference to the requst router
    * @type {Router}
    */
    this.router = auth.router.createChildRouter('local');

    this.router.addRoute({
      route: '/',
      handlers: { post: this.authenticate.bind(this) }
    }, {
      route: '/changepass',
      handlers: { post: this.changePasswordHandler.bind(this) }
    }, {
      route: '/forgotpass',
      handlers: { post: this.forgotPasswordHandler.bind(this) }
    }, {
      route: '/register',
      handlers: { post: this.registerHandler.bind(this) }
    }, {
      route: '/resetpass',
      handlers: { post: this.resetPasswordHandler.bind(this) }
    });
    auth.permissions.secureRoute(`${this.router.path}/changepass`, 'post', ['write:me']);
    auth.unsecureRoute(`${this.router.path}/`, 'post');
    auth.unsecureRoute(`${this.router.path}/register`, 'post');
    auth.unsecureRoute(`${this.router.path}/forgotpass`, 'post');
    auth.unsecureRoute(`${this.router.path}/resetpass`, 'post');

    server.api.addMiddleware((req, res, next) => {
      const token = req.session && req.session.token;
      if(token && !req.headers.Authorization) {
        req.headers.Authorization = `Bearer ${token}`;
      }
      next();
    });

    this.setReady();
  }
  /**
  * Performs authentication
  * @param {ClientRequest} req
  * @param {ServerResponse} res
  * @param {Function} next
  */
  async authenticate(req, res, next) {
    const { email, password } = req.body;
    if(!email || !password) {
      return next(AuthError.Authenticate('Must provide user login details'));
    }
    let user;
    try {
      [user] = await this.users.find({ email });
      if(!user) {
        throw AuthError.Authenticate('invalid login credentials provided');
      }
      await this.checkLocking(user);
    } catch(e) {
      return next(e);
    }
    try {
      await PasswordUtils.compare(password, user.password);
      await this.updateUser(user._id, { failedLoginAttempts: 0 });

      req.session.token = await AuthToken.generate('local', user);
      res.json({ token: req.session.token });

    } catch(e) {
      try {
        await this.applyLocking(user);
      } catch(e2) {
        return next(e2);
      }
      next(e);
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
    return this.users.update(isId ? { _id: userIdOrQuery } : userIdOrQuery, await this.validate(updateData));
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
  * Handles updating a user password
  * @param {ClientRequest} req
  * @param {ServerResponse} res
  * @param {Function} next
  */
  async changePasswordHandler(req, res, next) {
    try {
      const password = await PasswordUtils.generate(req.body.password);
      await this.updateUser(req.auth.user._id, { password });
      res.status(res.StatusCodes.Success.NoContent).end();
    } catch(e) {
      next(e);
    }
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
  * Handles resetting a user password
  * @param {ClientRequest} req
  * @param {ServerResponse} res
  * @param {Function} next
  */
  async resetPasswordHandler(req, res, next) {
    const { email, token, password } = req.body;
    try {
      await PasswordUtils.validateReset(email, token);
      await this.updateUser({ email }, { password: await PasswordUtils.generate(password) });
      await PasswordUtils.deleteReset(token);
      res.send({ message: 'Password updated successfully.' });
    } catch(e) {
      res.sendError(res.StatusCodes.Error.User, e);
    }
  }
}

module.exports = LocalAuthModule;
