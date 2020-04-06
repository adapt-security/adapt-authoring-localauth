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
    const [ auth, server ] = await this.app.waitForModule('auth', 'server');

    auth.authentication.registerPlugin('local', this);

    server.api.addRoute({
      route: '/auth/local/register',
      handlers: { post: this.registerHandler.bind(this) }
    }, {
      route: '/auth/local/disavow',
      handlers: { post: this.disavowHandler.bind(this) }
    });
    auth.unsecureRoute('/api/auth/local/register', 'post');
    auth.unsecureRoute('/api/auth/local/disavow', 'post');

    this.setReady();
  }
  async authenticate(req, res, next) {
    let token;
    try {
      const users = await this.app.waitForModule('users');
      const [user] = await users.find({ email: req.body.username, password: req.body.password });
      if(!user) {
        throw AuthError.Authenticate('invalid login credentials');
      }
      token = await AuthToken.generate(user);

    } catch(e) {
      return next(e);
    }
    req.session.token = token;
    res.end();
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
