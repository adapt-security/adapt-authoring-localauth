const { App } = require('adapt-authoring-core');
const bcrypt = require('bcryptjs');

class PasswordUtils {
  static async getConfig(...keys) {
    const localauth = await App.instance.waitForModule('localauth');

    if(keys.length === 1) {
      return localauth.getConfig(keys[0]);
    }
    return keys.reduce((m,k) => {
      m[k] = auth.getConfig(k);
      return m;
    }, {});
  }
  static compare(plainPassword, hash) {
    return new Promise((resolve, reject) => {
      bcrypt.compare(plainPassword, hash, (error, isValid) => {
        if(error || !isValid) {
          return reject(new Error(`Password doesn't match`));
        }
        resolve();
      });
    });
  }
  static generate(plainPassword) {
    return new Promise(async (resolve, reject) => {
      const { saltRounds } = await PasswordUtils.getConfig('saltRounds');
      bcrypt.genSalt(saltRounds, (saltError, salt) => {
        if(saltError) {
          return reject(saltError);
        }
        bcrypt.hash(plainPassword, salt, async (hashError, hash) => {
          if(hashError) {
            return reject(hashError);
          }
          resolve(hash);
        });
      });
    });
  }
}

module.exports = PasswordUtils;
