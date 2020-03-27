const { AbstractModule } = require('adapt-authoring-core');
const { AuthError, AuthUtils } = require('adapt-authoring-auth');
const session = require('express-session');

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
    const [ auth, server ] = await this.app.waitForModule('auth', 'server');

    this.initSessions();

    auth.authentication.registerPlugin('local', this);

    server.api.addRoute({
      route: '/signup',
      handlers: { post: this.signUpHandler.bind(this) }
    });
    auth.unsecureRoute('/api/signup', 'post');

    this.setReady();
  }
  async initSessions() {
    const [ mongodb, server ] = await this.app.waitForModule('mongodb', 'server');
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

    server.api.addMiddleware((req, res, next) => {
      const token = req.session && req.session.token;
      if(token) req.headers.Authorization = `Bearer ${token}`;
      next();
    });
  }
  async authenticate(req, res, next) {
    const users = await this.app.waitForModule('users');
    const [user] = await users.find({ email: req.body.username, password: req.body.password });
    if(!user) {
      throw AuthError.Authenticate('invalid login credentials');
    }
    req.session.token = await AuthUtils.generateToken(user);
    res.end();
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
