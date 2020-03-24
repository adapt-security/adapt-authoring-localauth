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

    auth.authentication.registerPlugin(this.authenticate.bind(this));

    server.api.addRoute({ route: '/signup', handlers: { post: this.signUpHandler.bind(this) } });
    auth.unsecureRoute('/api/signup', 'post');

    this.auth = auth;
    this.setReady();
  }
  async signUpHandler(req, res, next) {
    try {
      res.json(await this.auth.registerUser(req.body));
    } catch(e) {
      next(e);
    }
  }
  async authenticate(data) {
    if(data.header.type !== 'Basic') {
      return;
    }
    const users = await this.app.waitForModule('users');
    const [ email, password ] = Buffer.from(data.header.value, 'base64').toString().split(':');
    const [user] = await users.find({ email, password });
    if(!user) {
      throw AuthError.Authenticate('Invalid login credentials');
    }
    return { email: user.email, isNew: false };
  }
}

module.exports = LocalAuthModule;
