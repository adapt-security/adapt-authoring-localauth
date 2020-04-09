const { AbstractModule } = require('adapt-authoring-core');
const { AuthError, AuthToken } = require('adapt-authoring-auth');
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
    const [ auth, jsonschema, server ] = await this.app.waitForModule('auth', 'jsonschema', 'server');

    jsonschema.extendSchema('user', 'localauthuser');

    auth.authentication.registerPlugin('local', this);
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
    try {
      if(!req.body.email || !req.body.password) {
        const e = new Error('Must provide user login details');
        e.statusCode = res.StatusCodes.Error.User;
        throw e;
      }
      const users = await this.app.waitForModule('users');
      const [user] = await users.find({ email: req.body.email, password: req.body.password });
      if(!user) {
        throw AuthError.Authenticate('invalid login credentials');
      }
      req.session.token = await AuthToken.generate(user);
      res.end();

    } catch(e) {
      return next(e);
    }
  }
  /**
  * Registers a new user
  * @param {Object} data Data to be used for doc creation
  * @return {Promise} Resolves with the new user's data
  */
  async register(data) {
    const users = await this.app.waitForModule('users');
    return users.insert(data);
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
