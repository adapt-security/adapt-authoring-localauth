const { AbstractModule } = require('adapt-authoring-core');
const { AuthError, AuthToken } = require('adapt-authoring-auth');
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
    const [ auth, jsonschema, server, users ] = await this.app.waitForModule('auth', 'jsonschema', 'server', 'users');

    jsonschema.extendSchema('user', 'localauthuser');

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
      route: '/register',
      handlers: { post: this.registerHandler.bind(this) }
    });
    auth.unsecureRoute(`${this.router.path}/`, 'post');
    auth.unsecureRoute(`${this.router.path}/register`, 'post');

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
      [user] = (await this.users.find({ email }));
      if(!user) {
        throw AuthError.Authenticate('invalid login credentials provided');
      }
      await this.checkLocking(user);
    } catch(e) {
      return next(e);
    }
    try {
      await PasswordUtils.compare(password, user.password);
      await this.users.update({ _id: user._id }, { failedLoginAttempts: 0 });

      req.session.token = await AuthToken.generate('local', user);
      res.json({ token: req.session.token });

    } catch(e) {
      try { await this.applyLocking(user); }
      catch(e2) { return next(e2); }
      next(e);
    }
  }
  async checkLocking(user) {
    const tempLockEndTime = new Date(user.lastFailedLoginAttempt).getTime()+(this.getConfig('temporaryLockDuration')*1000);
    const tempLockRemainingSecs = Math.round((tempLockEndTime-Date.now())/1000);

    if(user.isPermLocked) {
      throw AuthError.Authenticate('account is permanently locked, please contact an administrator for assistance');
    }
    if(user.isTempLocked) {
      if(tempLockRemainingSecs > 0) {
        throw AuthError.Authenticate(`account is temporarily locked, please try again in ${LocalAuthModule.formatRemainingTime(tempLockRemainingSecs)}`);
      }
      await this.users.update({ _id: user._id }, { isTempLocked: false });
    }
  }
  async applyLocking(user) {
    const failedAttempts = user.failedLoginAttempts+1;
    const isTempLocked = (failedAttempts % this.getConfig('failsUntilTemporaryLock')) === 0;
    const isPermLocked = failedAttempts >= this.getConfig('failsUntilPermanentLock');
    const lastFailedLoginAttempt = new Date().toISOString();
    let errorMsg;

    if(isPermLocked) {
      errorMsg = 'account has been permanently locked due to too many invalid login attempts';
    } else if(isTempLocked) {
      errorMsg = 'account has been temporarily locked due to too many invalid login attempts';
    } else {
      errorMsg = 'invalid login credentials provided';
    }
    await this.users.update({ _id: user._id }, { failedLoginAttempts, isTempLocked, isPermLocked, lastFailedLoginAttempt });

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
    const password = await PasswordUtils.generate(data.password);
    return auth.findOrCreateUser('local', data.email, { ...data, password });
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
}

module.exports = LocalAuthModule;
