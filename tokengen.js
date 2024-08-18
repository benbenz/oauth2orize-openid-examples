

var jwt = require('jsonwebtoken') 
var db = require('./db')
var openid = require('oauth2orize-openid')


/// Token ID generation

function generateIdToken(client, user) {

    openid().utils.tokenize(user);

    const payload = {
        sub: user.id,  // Subject - the unique identifier of the user
        aud: client.id,  // Audience - the client ID
        iss: 'https://nomo.community.com',  // Issuer - your authorization server URL
        exp: Math.floor(Date.now() / 1000) + (60 * 60),  // Expiration time - 1 hour
        iat: Math.floor(Date.now() / 1000),  // Issued at
        nonce: user.nonce  // Nonce to mitigate replay attacks
    };
  
    const id_token = jwt.sign(payload, config.jwtSecret);  // Sign the token with your secret key
    return id_token;
  }
  
function generateAccessToken(user, client) {
    const token = utils.uid(256);  // Generate a random token
    db.accessTokens.save(token, user.id, client.clientId, function(err) {
        if (err) { return done(err); }
        done(null, token);
    });
}

function generateAuthorizationCode(client, redirectURI, user) {
    const code = utils.uid(16);  // Generate a random authorization code
    db.authorizationCodes.save(code, client.id, redirectURI, user.id, function(err) {
        if (err) { return done(err); }
        done(null, code);
    });
}


exports.generateIdToken = generateIdToken;
exports.generateAccessToken = generateAccessToken;
exports.generateAuthorizationCode = generateAuthorizationCode;