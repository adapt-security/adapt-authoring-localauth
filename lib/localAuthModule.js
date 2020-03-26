const { AbstractModule } = require('adapt-authoring-core');
const { AuthError, AuthUtils } = require('adapt-authoring-auth');
const session = require('session');

const MongoDBStore = require('connect-mongodb-session')(session);
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
    const [auth, mongodb, server] = await this.app.waitForModule('auth', 'mongodb', 'server');

    auth.authentication.registerPlugin('local', this);

    const mongoStore = new MongoDBStore({
      collection: AuthUtils.getConfig('sessionsCollection'),
      uri: mongodb.connectionURI
    });
    server.expressApp.use(session({
      name: 'adapt.sid',
      secret: AuthUtils.getConfig('sessionSecret'),
      cookie: { maxAge: AuthUtils.getConfig('sessionLifespan') },
      store: mongoStore,
      resave: false,
      saveUninitialized: true
    }));
    mongoStore.on('error', e => AuthUtils.log('error', e));

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
