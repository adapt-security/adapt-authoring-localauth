const { AbstractModule } = require('adapt-authoring-core');
const { AuthError } = require('adapt-authoring-auth');
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
    const [auth, server] = await this.app.waitForModule('auth', 'server');

    auth.authentication.registerPlugin('local', this);

    server.api.addRoute({ route: '/signup', handlers: { post: this.signUpHandler.bind(this) } });
    auth.unsecureRoute('/api/signup', 'post');

    this.setReady();
  }
  async authenticate(req) {
    const users = await this.app.waitForModule('users');
    const [user] = await users.find({ email: req.body.username, password: req.body.password });
    if(!user) {
      throw AuthError.Authenticate('Invalid login credentials');
    }
    return user;
  }
  async signUpHandler(req, res, next) {
    try {
      const users = await this.app.waitForModule('users');
      res.json(await users.insert(req.body));
    } catch(e) {
      next(e);
    }
  }
}

module.exports = LocalAuthModule;
