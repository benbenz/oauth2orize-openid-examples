/**
 * Module dependencies.
 */

var oauth2orize = require('oauth2orize')
  , oauth2orize_ext = require('oauth2orize-openid') // require extentions.
  , passport = require('passport')
  , login = require('connect-ensure-login')
  , db = require('./db')
  , utils = require('./utils')
  , dotenv = require('dotenv') 
  , { generateIdToken, verifyIdToken , generateRefreshToken , verifyRefreshToken } = require('./tokengen')


dotenv.config()

// create OAuth 2.0 server
var server = oauth2orize.createServer();

// Register serialialization and deserialization functions.
//
// When a client redirects a user to user authorization endpoint, an
// authorization transaction is initiated.  To complete the transaction, the
// user must authenticate and approve the authorization request.  Because this
// may involve multiple HTTP request/response exchanges, the transaction is
// stored in the session.
//
// An application must supply serialization functions, which determine how the
// client object is serialized into the session.  Typically this will be a
// simple matter of serializing the client's ID, and deserializing by finding
// the client by ID from the database.

server.serializeClient(function(client, done) {
  return done(null, client.id);
});

server.deserializeClient(function(id, done) {
  db.clients.find(id, function(err, client) {
    if (err) { return done(err); }
    return done(null, client);
  });
});

// Register supported OpenID Connect 1.0 grant types.

// Implicit Flow

// id_token grant type.
server.grant(oauth2orize_ext.grant.idToken(function(client, user, done){
  var id_token;
  // Do your lookup/token generation.
  // ... id_token =

  done(null, id_token);
}));

// 'id_token token' grant type.
server.grant(oauth2orize_ext.grant.idTokenToken(
  function(client, user, done){
    var token;
    // Do your lookup/token generation.
    // ... token =

    done(null, token);
  },
  function(client, user, req, done){
    var id_token;
    // Do your lookup/token generation.
    // ... id_token =
    done(null, id_token);
  }
));

// Hybrid Flow

// 'code id_token' grant type.
server.grant(oauth2orize_ext.grant.codeIdToken(
  function(client, redirect_uri, user, done){
    var code;
    // Do your lookup/token generation.
    // ... code =

    done(null, code);
  },
  function(client, user, done){
    var id_token;
    // Do your lookup/token generation.
    // ... id_token =
    done(null, id_token);
  }
));

// 'code token' grant type.
server.grant(oauth2orize_ext.grant.codeToken(
  function(client, user, done){
    var token;
    // Do your lookup/token generation.
    // ... id_token =
    done(null, token);
  },
  function(client, redirect_uri, user, done){
    var code;
    // Do your lookup/token generation.
    // ... code =

    done(null, code);
  }
));

// 'code id_token token' grant type.
server.grant(oauth2orize_ext.grant.codeIdTokenToken(
 function(client, user, done){
    var token;
    // Do your lookup/token generation.
    // ... id_token =
    done(null, token);
  },
  function(client, redirect_uri, user, done){
    var code;
    // Do your lookup/token generation.
    // ... code =

    done(null, code);
  },
  function(client, user, done){
    var id_token;
    // Do your lookup/token generation.
    // ... id_token =
    done(null, id_token);
  }
));


// server.grant(oauth2orize.grant.refreshToken(function(client, refreshToken, scope, done) {

// }));



// Register supported Oauth 2.0 grant types.
//
// OAuth 2.0 specifies a framework that allows users to grant client
// applications limited access to their protected resources.  It does this
// through a process of the user granting access, and the client exchanging
// the grant for an access token.

// Grant authorization codes.  The callback takes the `client` requesting
// authorization, the `redirectURI` (which is used as a verifier in the
// subsequent exchange), the authenticated `user` granting access, and
// their response, which contains approved scope, duration, etc. as parsed by
// the application.  The application issues a code, which is bound to these
// values, and will be exchanged for an access token.

server.grant(oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
  var code = utils.uid(16)
  
  db.authorizationCodes.save(code, client.id, redirectURI, user.id, function(err) {
    if (err) { return done(err); }
    done(null, code);
  });
}));

// Grant implicit authorization.  The callback takes the `client` requesting
// authorization, the authenticated `user` granting access, and
// their response, which contains approved scope, duration, etc. as parsed by
// the application.  The application issues a token, which is bound to these
// values.

server.grant(oauth2orize.grant.token(function(client, user, ares, done) {
    var token = utils.uid(256);
    var expiresIn = 3600;  // Set the token expiry time in seconds (e.g., 1 hour)
    var now = Math.floor(Date.now() / 1000);      

    db.accessTokens.save(token, user.id, client.clientId, now+expiresIn,function(err) {
        if (err) { return done(err); }
        done(null, token);
    });
}));

// Exchange authorization codes for access tokens.  The callback accepts the
// `client`, which is exchanging `code` and any `redirectURI` from the
// authorization request for verification.  If these values are validated, the
// application issues an access token on behalf of the user who authorized the
// code.

server.exchange(oauth2orize.exchange.code(function(client, code, redirectURI, done) {
  // db.authorizationCodes.find(code, function(err, authCode) {
  //   if (err) { return done(err); }
  //   if (client.id !== authCode.clientID) { return done(null, false); }
  //   if (redirectURI !== authCode.redirectURI) { return done(null, false); }
    
  //   var token = utils.uid(256)
  //   db.accessTokens.save(token, authCode.userID, authCode.clientID, function(err) {
  //     if (err) { return done(err); }
  //     done(null, token);
  //   });
  // });
  db.authorizationCodes.find(code, function(err, authCode) {
    if (err) { return done(err); }
    if (client.clientId !== authCode.clientId) { return done(null, false); }
    if (redirectURI !== authCode.redirectURI) { return done(null, false); }

    db.users.find(authCode.userId, function (err, user) {

      if(err) return done(err)

      // Generate access_token, id_token, and refresh_token
      var id_token = generateIdToken(client, user);
      var accessToken = id_token
      var refreshToken = utils.uid(256);
      var expiresIn = 3600;  // Set the token expiry time in seconds (e.g., 1 hour)
      var now = Math.floor(Date.now() / 1000);      

      // Save access_token and refresh_token in the database
      db.accessTokens.save(accessToken, authCode.userId, authCode.clientId, now+expiresIn, function(err) {
        if (err) return done(err)
        db.refreshTokens.save(refreshToken, authCode.userId, authCode.clientId, now+expiresIn,function(err) {
            if (err) return done(err)
            // Return all tokens in the response
            done(null, accessToken, refreshToken, id_token);      
          });
      });
    });
  });

}));

// Exchange user id and password for access tokens.  The callback accepts the
// `client`, which is exchanging the user's name and password from the
// authorization request for verification. If these values are validated, the
// application issues an access token on behalf of the user who authorized the code.

server.exchange(oauth2orize.exchange.password(function(client, username, password, scope, done) {

    //Validate the client
    db.clients.findByClientId(client.clientId, function(err, localClient) {
        if (err) { return done(err); }
        if(localClient === null) {
            return done(null, false);
        }
        if(localClient.clientSecret !== client.clientSecret) {
            return done(null, false);
        }
        //Validate the user
        db.users.findByUsername(username, function(err, user) {
            if (err) { return done(err); }
            if(user === null) {
                return done(null, false);
            }
            if(password !== user.password) {
                return done(null, false);
            }
            //Everything validated, return the token
            // var token = utils.uid(256);
            // db.accessTokens.save(token, user.id, client.clientId, function(err) {
            //     if (err) { return done(err); }
            //     done(null, token);
            // });

            // Generate access_token, id_token, and refresh_token
            var idToken = generateIdToken(client, user);
            var accessToken = idToken
            var refreshToken = utils.uid(256);
            var expiresIn = 3600;  // Set the token expiry time in seconds (e.g., 1 hour)
            var now = Math.floor(Date.now() / 1000);            

            // Save access_token and refresh_token in the database
            db.accessTokens.save(accessToken, client.clientId, user.id, now+expiresIn, function(err) {
              if (err) return done(err)
              db.refreshTokens.save(refreshToken, client.clientId, user.id, now+expiresIn, function(err) {
                  if (err) return done(err)
                  // Return all tokens in the response
                  done(null, accessToken, refreshToken, {id_token: idToken, expires_in : expiresIn});      
                });
            });            

        });
    });
}));


// Exchange refresh tokens for access tokens and id tokens.
server.exchange(oauth2orize.exchange.refreshToken(function(client, refreshToken, scope, done) {
  db.refreshTokens.find(refreshToken, function(err, token) {
    if (err) { return done(err); }
    if (!token) { return done(null, false); }

    // Check if the refresh token belongs to the client
    if (client.clientId !== token.clientId) { return done(null, false); }

    // TODO CHECK EXPIRATION TOO !!!!!!
    const now = Math.floor(Date.now() / 1000);
    if (token.expiresAt && token.expiresAt < now) {
      return done(null, false, { message: 'Refresh token has expired' });
    }    

    // Generate new access_token and id_token
    db.users.find(token.userId, function (err, user) {
      var idToken = generateIdToken(client, user);
      var refreshToken = utils.uid(256);
      var accessToken = idToken
      var expiresIn = 3600;  // Set the token expiry time in seconds (e.g., 1 hour)
      // Save new access_token in the database
      db.accessTokens.save(accessToken, token.userID, token.clientID, now + expiresIn, function(err) {
        if (err) { return done(err); }
          db.refreshTokens.save(refreshToken, client.clientId, user.id, now + expiresIn, function(err) {
              if (err) return done(err)
              // Return new tokens in the response
              done(null, accessToken, refreshToken, { id_token: idToken , expires_in: expiresIn });
          });
      });
    });
  });
}));



function verifyTokenRequest(req, res) {
  const idToken = req.body.token;

  verifyIdToken(idToken, function(err, decoded) {
    if (err || !decoded) {
      return res.status(401).json({ error: err.message ?? 'Invalid ID token' });
    }

    // ID token is valid, return the decoded claims
    res.status(200).json({ claims: decoded });
  });
}

function addCustomClaims(req, res) {
  const claims = req.body.claims;
  const userId = req.body.userId;
  if (req.headers['content-type'] !== 'application/json') return res.status(415).json({ error: 'Server requires application/json' })
  if(!userId) {return res.status(400).json({ error: 'User ID is required' });}
  if(!claims) {return res.status(400).json({ error: 'Custom claims are required' });}

  db.users.addCustomClaims(userId, claims, function(err,user) {
    if(err) return res.status(400).json({ error: err.message });
    res.status(200).json({ error: 'Custom claims added successfully' });
  });

}

// Exchange the client id and password/secret for an access token.  The callback accepts the
// `client`, which is exchanging the client's id and password/secret from the
// authorization request for verification. If these values are validated, the
// application issues an access token on behalf of the client who authorized the code.

server.exchange(oauth2orize.exchange.clientCredentials(function(client, scope, done) {

    //Validate the client
    db.clients.findByClientId(client.clientId, function(err, localClient) {
        if (err) { return done(err); }
        if(localClient === null) {
            return done(null, false);
        }
        if(localClient.clientSecret !== client.clientSecret) {
            return done(null, false);
        }
        var expiresIn = 3600;  // Set the token expiry time in seconds (e.g., 1 hour)
        var now = Math.floor(Date.now() / 1000);      
          
        var token = utils.uid(256);
        //Pass in a null for user id since there is no user with this grant type
        db.accessTokens.save(token, null, client.clientId, now+expiresIn, function(err) {
            if (err) { return done(err); }
            done(null, token);
        });
    });
}));

// user authorization endpoint
//
// `authorization` middleware accepts a `validate` callback which is
// responsible for validating the client making the authorization request.  In
// doing so, is recommended that the `redirectURI` be checked against a
// registered value, although security requirements may vary accross
// implementations.  Once validated, the `done` callback must be invoked with
// a `client` instance, as well as the `redirectURI` to which the user will be
// redirected after an authorization decision is obtained.
//
// This middleware simply initializes a new authorization transaction.  It is
// the application's responsibility to authenticate the user and render a dialog
// to obtain their approval (displaying details about the client requesting
// authorization).  We accomplish that here by routing through `ensureLoggedIn()`
// first, and rendering the `dialog` view. 

exports.authorization = [
  login.ensureLoggedIn(),
  server.authorization(function(clientID, redirectURI, done) {
    db.clients.findByClientId(clientID, function(err, client) {
      if (err) { return done(err); }
      // WARNING: For security purposes, it is highly advisable to check that
      //          redirectURI provided by the client matches one registered with
      //          the server.  For simplicity, this example does not.  You have
      //          been warned.
      if(client.redirectURI !== redirectURI) { return done(null, false); } // done here
      return done(null, client, redirectURI);
    });
  }),
  function(req, res){
    res.render('dialog', { transactionID: req.oauth2.transactionID, user: req.user, client: req.oauth2.client });
  }
]

// user decision endpoint
//
// `decision` middleware processes a user's decision to allow or deny access
// requested by a client application.  Based on the grant type requested by the
// client, the above grant middleware configured above will be invoked to send
// a response.

exports.decision = [
  login.ensureLoggedIn(),
  server.decision()
]


// token endpoint
//
// `token` middleware handles client requests to exchange authorization grants
// for access tokens.  Based on the grant type being exchanged, the above
// exchange middleware will be invoked to handle the request.  Clients must
// authenticate when making requests to this endpoint.

exports.token = [
  passport.authenticate(['basic', 'oauth2-client-password', 'oauth2-resource-owner-password'], { session: false }),
  server.token(),
  server.errorHandler()
]

exports.refresh = [
  passport.authenticate(['client-id'], { session: false }),
  server.token(),
  server.errorHandler()
]

exports.verify = [
  passport.authenticate(['basic','oauth2-client-password'], { session: false }),
  verifyTokenRequest 
]

exports.claims = [
  passport.authenticate(['basic','oauth2-client-password'], { session: false }),
  addCustomClaims 
]