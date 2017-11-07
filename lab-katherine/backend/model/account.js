'use strict';

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const httpErrors = require('http-errors');
import {randomBytes} from 'crypto';

const accountSchema = mongoose.Schema({
  username: {type: String, required: true, unique: true},
  email: {type: String, required: true, unique: true},
  passwordHash: {type: String, required: true},
  googleOAuth: {type: Boolean, default: false},
  tokenSeed: {type: String, required: true, unique: true},
  created: {type: Date, default: () => new Date()},
});

// Instance methods
accountSchema.methods.passwordVerify = function(password) {
  return bcrypt.compare(password, this.passwordHash)
    .then(correctPassword => {
      if(!correctPassword)
        throw httpErrors(401, '__AUTH_ERROR__ incorrect password');
      return this;
    });
};

accountSchema.methods.tokenCreate = function() {
  this.tokenSeed = crypto.randomBytes(64).toString('hex');
  return this.save()
    .then(account => {
      let options = {expiresIn: '7d'};
      return jwt.sign({tokenSeed: account.tokenSeed}, process.env.CLOUD_SECRET, options);
    });
};

accountSchema.methods.update = function(data) {
  let {password} = data;
  delete data.password;
  return bcrypt.hash(password, 8)
    .then(passwordHash => {
      this.username = data.username;
      this.email = data.email;
      this.passwordHash = passwordHash;
      return this.save();
    });
};

const Account = module.exports = mongoose.model('account', accountSchema);

// Data is going to contain {username, email, and password}
Account.create = function(data) {
  // Hash password
  let {password} = data;
  delete data.password;
  return bcrypt.hash(password, 8)
    .then(passwordHash => {
      data.passwordHash = passwordHash;
      // Generate a tokenSeed
      data.tokenSeed = crypto.randomBytes(64).toString('hex');
      return new Account(data).save();
    });
};

Account.handleGoogleOAuth = function(openIDProfile){
  return Account.findOne({email: openIDProfile.email})
    .then(account => {
      if (account) {
        if(account.googleOAuth)
          return account;
        throw new Error('account found but not connected to Google');
      }
      return new Account({
        username: openIDProfile.email.split('@')[0],
        email: openIDProfile.email,
        passwordHash: randomBytes(32).toString('hex'),
        tokenSeed: randomBytes(32).toString('hex'),
        googleOAuth: true,
      })
        .save();
    });
};
