const { AbstractModule } = require('adapt-authoring-core');
const { AuthError, AuthToken } = require('adapt-authoring-auth');
/**
* Module which implements username/password (local) authentication
* @extends {AbstractModule}
*/
class LocalAuthModule extends AbstractModule {
  constructor(...args) {
    super(...args);
    this.init();
  }
  async init() {
    const [ auth, jsonschema, server ] = await this.app.waitForModule('auth', 'jsonschema', 'server');

    jsonschema.extendSchema('user', 'localauthuser');

    auth.authentication.registerPlugin('local', this);

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
  async register(data) {
    const users = await this.app.waitForModule('users');
    return users.insert(data);
  }
  async disavow(_id) {
    AuthToken.revoke({ _id });
  }
  async registerHandler(req, res, next) {
    try {
      res.json(await this.register(req.body));
    } catch(e) {
      next(e);
    }
  }
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
