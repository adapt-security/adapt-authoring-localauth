const { AbstractModule } = require('adapt-authoring-core');
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
  }
  async authenticate(req) {
    const authData = req.get('Authorization');
    console.log(authData);
  }
}

module.exports = LocalAuthModule;
