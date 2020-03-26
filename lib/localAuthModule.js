const { AbstractModule } = require('adapt-authoring-core');
const { AuthError } = require('adapt-authoring-auth');
const passport = require('passport');
const LocalStrategy = require('passport-local');
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

    passport.use(new LocalStrategy(this.verifyUser));

    auth.authentication.registerPlugin(this.authenticate.bind(this));

    server.api.addRoute({ route: '/signup', handlers: { post: this.signUpHandler.bind(this) } });
    auth.unsecureRoute('/api/signup', 'post');

    this.auth = auth;

    this.setReady();
  }
  async signUpHandler(req, res, next) {
    try {
      res.json(await this.auth.authentication.registerUser(req.body));
    } catch(e) {
      next(e);
    }
  }
  async authenticate(data) {
    if(data.header.type !== 'Basic') {
      return;
    }
  }
  async verifyUser(email, password, done) {
    const users = await this.app.waitForModule('users');
    const [user] = await users.find({ email, password });
    if(!user) {
      return done(AuthError.Authenticate('Invalid login credentials'));
    }
    done(null, { email: user.email, isNew: false });
  }
}

module.exports = LocalAuthModule;
