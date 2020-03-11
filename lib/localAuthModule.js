const { AbstractModule } = require('adapt-authoring-core');
const { AuthError } = require('adapt-authoring-auth');
/**
* Module which implements username/password (local) authentication
* @extends {AbstractModule}
*/
class LocalAuthModule extends AbstractModule {
  constructor(...args) {
    super(...args);
    this.app.waitForModule('auth').then(a => {
      a.registerAuthenticator(this.authenticate.bind(this));
    });
  registerUser() {
    const users = this.app.waitForModule('users');
    return async (req, res, next) => {
      console.log('LocalAuthModule#registerUser');
      const [user] = await users.find(users.schemaName, users.collectionName, { email: req.body.email });

      if(user) {
        return next(AuthError.Authenticate('Cannot create new user, user already exists'));
      }
      try {
        await users.insert(users.schemaName, users.collectionName, req.body);
        await this.authenticate({}, res, next);
      } catch(e) {
        next(e);
      }
    };
  }
  async authenticate(req) {
    const authData = req.get('Authorization');
    console.log(authData);
  }
}

module.exports = LocalAuthModule;
