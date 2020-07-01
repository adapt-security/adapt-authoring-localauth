const { AbstractModule } = require('adapt-authoring-core');
const { AuthError, AuthToken } = require('adapt-authoring-auth');

const PasswordUtils = require('./passwordUtils');
/**
* Module which implements username/password (local) authentication
* @extends {AbstractModule}
*/
class LocalAuthModule extends AbstractModule {
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
    }, {
      route: '/disavow',
      handlers: { post: this.disavowHandler.bind(this) }
    });
    auth.unsecureRoute(`${this.router.path}/`, 'post');
    auth.unsecureRoute(`${this.router.path}/register`, 'post');
    auth.unsecureRoute(`${this.router.path}/disavow`, 'post');

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
    try {
      const [user] = await this.users.find({ email });

      await this.verifyPassword(req.body, user);

      req.session.token = await AuthToken.generate(user);
      res.json({ token: req.session.token });

    } catch(e) {
      return next(e);
    }
  }
  async verifyPassword(reqData, user) {
    if(!user) {
      throw AuthError.Authenticate(`Couldn't find user with email '${email}'`);
    }
    let failedAttempts = user.failedAttempts;
    const permFails = this.getConfig('failsUntilPermanentLock');
    const tempFails = this.getConfig('failsUntilTemporaryLock');
    const tempLockEndTime = new Date(user.lastFailedLoginAttempt).getTime()+this.getConfig('temporaryLockDuration');
    const tempLockRemaining = tempLockEndTime-Date.now();

    if(user.isPermLocked) {
      throw AuthError.Authenticate('account is permanently locked, please contact an administrator for assistance');
    }
    if(user.isTempLocked) {
      if(tempLockRemaining > 0) {
        throw AuthError.Authenticate(`account is temporarily locked, please try again in ${Math.round(tempLockRemaining/1000)} seconds`);
      }
      await this.users.update({ _id: user._id }, { isTempLocked: false });
    }
    try {
      await PasswordUtils.compare(reqData.password, user.password);
      await this.users.update({ _id: user._id }, { failedAttempts: 0 });
    } catch(e) {
      failedAttempts++;

      const updateData = { failedAttempts, lastFailedLoginAttempt: new Date().toISOString() };
      let errorMsg;

      if(failedAttempts >= permFails) {
        errorMsg = 'account has been permanently locked due to too many invalid login attempts';
        updateData.isPermLocked = true;
      } else if((failedAttempts % tempFails) === 0) {
        errorMsg = 'account has been temporarily locked due to too many invalid login attempts';
        updateData.isTempLocked = true;
      } else {
        errorMsg = 'invalid login credentials provided';
      }
      await this.users.update({ _id: user._id }, updateData);
      this.log('warn', `failed login attempt recorded for ${user.email} (${failedAttempts})`);

      throw AuthError.Authenticate(errorMsg);
    }
  }
  /**
  * Registers a new user
  * @param {Object} data Data to be used for doc creation
  * @return {Promise} Resolves with the new user's data
  */
  async register(data) {
    const jsonschema = await this.app.waitForModule('jsonschema');
    await jsonschema.validate('localauthuser', data);
    data.password = await PasswordUtils.generate(data.password);
    return this.users.insert(data, { validate: false });
  }
  /**
  * Revokes access for a single token
  * @param {String} _id Token _id
  * @return {Promise} Resolves with the DB response
  */
  async disavow(_id) {
    return AuthToken.revoke({ _id });
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
      next(e);
    }
  }
  /**
  * Handles removing token data for an incoming user
  * @param {ClientRequest} req
  * @param {ServerResponse} res
  * @param {Function} next
  */
  async disavowHandler(req, res, next) {
    console.log(req.auth, req.session);
    /*
    try {
      const users = await this.app.waitForModule('users');
      res.json(await users.insert(req.body));
    } catch(e) {
      next(e);
    }
    */
  }
}

module.exports = LocalAuthModule;
