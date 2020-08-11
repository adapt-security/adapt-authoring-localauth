const { App } = require('adapt-authoring-core');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const passwordResetsCollectionName = 'passwordresets';

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
    if(!plainPassword) {
      return Promise.reject(new Error(`must provide password`));
    }
    if(!hash) {
      return Promise.reject(new Error(`must provide password hash`));
    }
    return new Promise((resolve, reject) => {
      bcrypt.compare(plainPassword, hash, (error, isValid) => {
        if(error || !isValid) {
          return reject(new Error(`P
          password doesn't match`));
        }
        resolve();
      });
    });
  }
  static generate(plainPassword) {
    if(!plainPassword) {
      return Promise.reject(new Error(`must provide password`));
    }
    return new Promise(async (resolve, reject) => {
      const jsonschema = await App.instance.waitForModule('jsonschema');
      const schema = { properties: { password: { type: 'string', format: 'password' } } };
      try {
        await jsonschema.validate(schema, { password: plainPassword });
      } catch(e) {
        reject(e);
      }
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
  static async createReset(email) {
    const [mongodb, users] = await App.instance.waitForModule('mongodb', 'users');
    const [user] = await users.find({ email });
    if(!user) {
      throw new Error('No matching user found');
    }
    if(!user.authTypes.includes('local')) {
      throw new Error(`User isn't authenticated with local auth`);
    }
    const lifespan = await this.getConfig('resetTokenLifespan');
    const { token } = await mongodb.insert(passwordResetsCollectionName, {
      email,
      expiresAt: new Date(Date.now()+lifespan).toISOString(),
      token: await this.getRandomHex()
    });
    return token;
  }
  static async getRandomHex(size = 32) {
    return new Promise((resolve, reject) => {
      crypto.randomBytes(size, (error, buffer) => {
        if(error) return reject(error);
        resolve(buffer.toString('hex'));
      });
    });
  }
  static async validateReset(email, token) {
    const [mongodb, users] = await App.instance.waitForModule('mongodb', 'users');
    const [user] = await users.find({ email });
    if(!user) {
      throw new Error('Invalid reset token');
    }
    const [tokenData] = await mongodb.find(passwordResetsCollectionName, { email, token });
    if(!tokenData) {
      throw new Error('No matching token found');
    }
    if(new Date(tokenData.expiresAt) < new Date()) {
      throw new Error('Token has expired');
    }
    return mongodb.delete('passwordresets', { _id: tokenData._id });
  }
}



module.exports = PasswordUtils;
