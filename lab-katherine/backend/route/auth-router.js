'use strict';

const {Router} = require('express');
const Account = require('../model/account.js');
const httpErrors = require('http-errors');
const basicAuth = require('../lib/basic-auth-middleware.js');
const superagent = require('superagent');

const authRouter = module.exports = new Router();

// create a backend route GET /oauth/google/code for
// handling google oauth
authRouter.get('/oauth/google', (req, res, next) => {
  console.log(req.query);
  if(!req.query.code){
    res.redirect(process.env.CLIENT_URL);
  } else {
    // exchange code and client secret and clientID for an access token
    superagent.post('https://www.googleapis.com/oauth2/v4/token')
      .type('form')
      .send({
        code: req.query.code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${process.env.API_URL}/oauth/google`,
        grant_type: 'authorization_code',
      })
      .then((res) => {
        console.log(res.body);
        if(!res.body.access_token)
          throw new Error('no access token');
        return res.body.access_token;
      })
      .then(accessToken => {
        return superagent.get('https://www.googleapis.com/plus/v1/people/me/openIdConnect')
          .set('Authorization', `Bearer ${accessToken}`);
      })
      .then(res => {
        // find an account or create an account
        return Account.handleGoogleOAuth(res.body);
      })
      .then(account => account.tokenCreate())
      .then(token => {
        res.cookie('X-CharityChoice-token', token);
        res.redirect(process.env.CLIENT_URL);
      })
      .catch(err => {
        console.error(err);
        res.cookie('X-CharityChoice-token', '');
        res.redirect(process.env.CLIENT_URL + '?error=oauth');
      });
  }
});

authRouter.post('/auth', (req, res, next) => {
  Account.create(req.body)
    .then(account => account.tokenCreate())
    .then(token => {
      res.json({token});
    })
    .catch(next);
});

authRouter.get('/auth', basicAuth, (req, res, next) => {
  req.account.tokenCreate()
    .then(token => {
      res.json({token});
    })
    .catch(next);
});

authRouter.put('/auth', basicAuth, (req, res, next) => {

  if (!req.body.username || !req.body.email || !req.body.password)
    return next(httpErrors(400, '__REQUEST_ERROR__ username, email, and password required'));

  req.account.update(req.body)
    .then(() => {
      res.sendStatus(200);
    })
    .catch(next);
});
