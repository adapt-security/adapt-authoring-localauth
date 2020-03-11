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

    this.auth = auth;
    auth.registerAuthenticator(this.authenticate.bind(this));

    server.api.addRoute({ route: '/signup', handlers: { post: this.signUpHandler() } });
    this.auth.unsecureRoute('/api/signup', 'post');

    this.setReady();
  }
  signUpHandler() {
    return async (req, res, next) => {
      try {
        res.json(await this.auth.registerUser(req.body));
      } catch(e) {
        next(e);
      }
    };
  }
  authenticate(data) {
    return new Promise((resolve, reject) => {
      if(data.header.type !== 'Basic') {
        return resolve(null);
      }
      this.app.waitForModule('users').then(users => {
        const [ email, password ] = Buffer.from(data.header.value, 'base64').toString().split(':');
        users.find({ email, password }).then(([user]) => {
          if(!user) {
            return reject(AuthError.Authenticate('Invalid login credentials'));
          }
          resolve({ email: user.email, isNew: false });
        }, reject);
      }, reject);
    });
  }
}

module.exports = LocalAuthModule;
