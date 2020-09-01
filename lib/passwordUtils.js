const { App } = require('adapt-authoring-core');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { promisify }  = require('util');

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
  static async compare(plainPassword, hash) {
    if(!plainPassword) {
      throw new Error(`must provide password`);
    }
    if(!hash) {
      throw new Error(`must provide password hash`);
    }
    try {
      const isValid = await promisify(bcrypt.compare)(plainPassword, hash);
      if(!isValid) throw new Error();
    } catch(e) {
      return reject(new Error(`Password doesn't match`));
    }
  }
  static async generate(plainPassword) {
    if(!plainPassword) {
      throw new Error(`must provide password`);
    }
    const jsonschema = await App.instance.waitForModule('jsonschema');
    const schema = { properties: { password: { type: 'string', format: 'password' } } };

    await jsonschema.validate(schema, { password: plainPassword });
    
    const saltRounds = await PasswordUtils.getConfig('saltRounds');
    const salt = await promisify(bcrypt.genSalt)(saltRounds);
    
    return promisify(bcrypt.hash)(plainPassword, salt);
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
  static async deleteReset(token) {
    const mongodb = await App.instance.waitForModule('mongodb');
    return mongodb.delete(passwordResetsCollectionName, { token });
  }
  static async getRandomHex(size = 32) {
    const buffer = await promisify(crypto.randomBytes)(size);
    return buffer.toString('hex');
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
  }
}



module.exports = PasswordUtils;
