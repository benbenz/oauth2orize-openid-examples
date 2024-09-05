/**
 * Module dependencies.
 */
var passport = require('passport')
  , LocalStrategy = require('passport-local').Strategy
  , BasicStrategy = require('passport-http').BasicStrategy
  , ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy
  , ResourceOwnerPasswordStrategy = require('passport-oauth2-resource-owner-password').Strategy
  , BearerStrategy = require('passport-http-bearer').Strategy
  , ClientIDStrategy = require('./clientidstrategy')
  , db = require('./db')



/**
 * LocalStrategy
 *
 * This strategy is used to authenticate users based on a username and password.
 * Anytime a request is made to authorize an application, we must ensure that
 * a user is logged in before asking them to approve the request.
 */
passport.use(new LocalStrategy(
  function(username, password, done) {
    db.users.findByUsername(username, function(err, user) {
      if (err) { return done(err); }
      if (!user) { return done(null, false); }
      if (user.password != password) { return done(null, false); }
      return done(null, user);
    });
  }
));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  db.users.find(id, function (err, user) {
    done(err, user);
  });
});


/**
 * BasicStrategy & ClientPasswordStrategy
 *
 * These strategies are used to authenticate registered OAuth clients.  They are
 * employed to protect the `token` endpoint, which consumers use to obtain
 * access tokens.  The OAuth 2.0 specification suggests that clients use the
 * HTTP Basic scheme to authenticate.  Use of the client password strategy
 * allows clients to send the same credentials in the request body (as opposed
 * to the `Authorization` header).  While this approach is not recommended by
 * the specification, in practice it is quite common.
 */
passport.use(new BasicStrategy(
  function(username, password, done) {
    db.clients.findByClientId(username, function(err, client) {
      if (err) { return done(err); }
      if (!client) { return done(null, false); }
      if (client.clientSecret != password) { return done(null, false); }
      return done(null, client);
    });
  }
));

passport.use(new ClientPasswordStrategy(
  function(clientId, clientSecret, done) {
    db.clients.findByClientId(clientId, function(err, client) {
      if (err) { return done(err); }
      if (!client) { return done(null, false); }
      if (client.clientSecret != clientSecret) { return done(null, false); }
      return done(null, client);
    });
  }
));

/**
 * BearerStrategy
 *
 * This strategy is used to authenticate either users or clients based on an access token
 * (aka a bearer token).  If a user, they must have previously authorized a client
 * application, which is issued an access token to make requests on behalf of
 * the authorizing user.
 */
passport.use(new BearerStrategy(
  function(accessToken, done) {
    db.accessTokens.find(accessToken, function(err, token) {
      if (err) { return done(err); }
      if (!token) { return done(null, false); }

      if(token.userID != null) {
          db.users.find(token.userID, function(err, user) {
              if (err) { return done(err); }
              if (!user) { return done(null, false); }
              // to keep this example simple, restricted scopes are not implemented,
              // and this is just for illustrative purposes
              var info = { scope: '*' }
              done(null, user, info);
          });
      } else {
          //The request came from a client only since userID is null
          //therefore the client is passed back instead of a user
          db.clients.findByClientId(token.clientID, function(err, client) {
             if(err) { return done(err); }
              if(!client) { return done(null, false); }
              // to keep this example simple, restricted scopes are not implemented,
              // and this is just for illustrative purposes
              var info = { scope: '*' }
              done(null, client, info);
          });
      }
    });
  }
));



passport.use(new ResourceOwnerPasswordStrategy(
  function(clientId, clientSecret, username, password, done) {
    db.clients.findByClientId(clientId, function (err, client) {
      // this strategy does not require clientSecret as it is intended to be used in cases
      // (such as mobile apps) which are inherintly insecure

      if (err) { return done(err); }
      if (!client) { return done(null, false); }

      db.users.findByUsername(username, function (err, user) {
        if (err) { return done(err); }
        if (!user) { return done(null, false); }
        //if (hashsum(user.salt + password) !== user.secret) { return done(null, false); }
        if( user.password != password ) { return done(null, false); }

        var info = { scope: '*' }
        return done(null, client, info);
      })
    });
  }
));


// Define how to verify the clientId
passport.use(new ClientIDStrategy(function(clientId, done) {
  // Look up the client by clientId in the database
  db.clients.findByClientId(clientId, function(err, client) {
    if (err) {
      return done(err);
    }
    if (!client) {
      return done(null, false, { message: 'Unknown client ID' });
    }
    // Return the client object if found
    return done(null, client);
  });
}));
