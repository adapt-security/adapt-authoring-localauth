import { App } from 'adapt-authoring-core';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { promisify } from 'util';

/** @ignore */ const passwordResetsCollectionName = 'passwordresets';
/**
 * Various utilities related to password functionality
 */
export default class PasswordUtils {
  /**
   * Retrieves a localauth config item
   * @return {Promise}
   */
  static async getConfig(...keys) {
    const localauth = await App.instance.waitForModule('localauth');

    if(keys.length === 1) {
      return localauth.getConfig(keys[0]);
    }
    return keys.reduce((m,k) => {
      m[k] = localauth.getConfig(k);
      return m;
    }, {});
  }
  /**
   * Compares a plain password to a hash
   * @param {String} plainPassword
   * @param {String} hash
   * @return {Promise}
   */
  static async compare(plainPassword, hash) {
    if(!plainPassword || !hash) {
      throw this.app.errors.INVALID_PARAMS;
    }
    try {
      const isValid = await promisify(bcrypt.compare)(plainPassword, hash);
      if(!isValid) throw new Error();
    } catch(e) {
      throw this.app.errors.INVALID_PASSWORD;
    }
  }
  /**
   * Generates a secure hash from a plain-text password
   * @param {String} plainPassword
   * @return {Promise} Resolves with the hash
   */
  static async generate(plainPassword) {
    if(!plainPassword) {
      throw this.app.errors.INVALID_PARAMS;
    }
    const jsonschema = await App.instance.waitForModule('jsonschema');
    const schema = { properties: { password: { type: 'string', format: 'password' } } };

    await jsonschema.validate(schema, { password: plainPassword });

    const saltRounds = await PasswordUtils.getConfig('saltRounds');
    const salt = await promisify(bcrypt.genSalt)(saltRounds);

    return promisify(bcrypt.hash)(plainPassword, salt);
  }
  /**
   * Creates a password reset token
   * @param {String} email The user's email address
   * @return {Promise} Resolves with the token value
   */
  static async createReset(email) {
    const [mongodb, users] = await App.instance.waitForModule('mongodb', 'users');
    const [user] = await users.find({ email });
    if(!user) {
      throw this.app.errors.NOT_FOUND
        .setData({ type: 'user' });
    }
    if(!user.authTypes.includes('local')) {
      this.log('error', `Failed to reset ${user._id} password, not authenticated with local auth`);
      throw this.app.errors.ACCOUNT_NOT_LOCALAUTHD;
    }
    // invalidate any previous tokens for this user
    await mongodb.getCollection(passwordResetsCollectionName).deleteMany({ email });

    const lifespan = await this.getConfig('resetTokenLifespan');
    const { token } = await mongodb.insert(passwordResetsCollectionName, {
      email,
      expiresAt: new Date(Date.now()+lifespan).toISOString(),
      token: await this.getRandomHex()
    });
    return token;
  }
  /**
   * Deletes a stored password reset token
   * @param {String} token The token value
   * @return {Promise}
   */
  static async deleteReset(token) {
    const mongodb = await App.instance.waitForModule('mongodb');
    return mongodb.delete(passwordResetsCollectionName, { token });
  }
  /**
   * Creates a random hex string
   * @param {Number} size Size of string
   * @return {Promise} Resolves with the string value
   */
  static async getRandomHex(size = 32) {
    const buffer = await promisify(crypto.randomBytes)(size);
    return buffer.toString('hex');
  }
  /**
   * Validates a password reset token
   * @param {String} email The user's email
   * @param {String} token The password reset token
   * @return {Promise} Rejects on invalid token
   */
  static async validateReset(email, token) {
    if(!email || !token) {
      throw this.app.errors.INVALID_PARAMS;
    }
    const [mongodb, users] = await App.instance.waitForModule('mongodb', 'users');
    const [user] = await users.find({ email });
    if(!user) {
      throw this.app.errors.NOT_FOUND
        .setData({ type: 'user' });
    }
    const [tokenData] = await mongodb.find(passwordResetsCollectionName, { email, token });
    if(!tokenData) {
      throw this.app.errors.NOT_FOUND
        .setData({ type: 'authtoken' });
    }
    if(new Date(tokenData.expiresAt) < new Date()) {
      throw this.app.errors.AUTH_TOKEN_EXPIRED;
    }
  }
}