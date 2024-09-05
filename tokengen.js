

var jwt = require('jsonwebtoken') 
var db = require('./db')
var openid = require('oauth2orize-openid')

const jwtSecretAccess = "sajkdhri345y78ewqndsv29480rtgfudjskahefkwjl--jqj832vryobr38wucrwklbcruleqb99urxl9eqb3ruel92brul9bru3489558y9wdjlal===fkvcas9nrl2"
const jwtSecretRefresh = "8uriu49t54rtnecwdbvdkdxw3tbkretyk4w7beuxkqlw021bqrl9k437rl3bqyrkrb732br38xsnvksaxlie3i9lbrbqdlxwqlnc-2t0t-efddfs=cdf845839fk"

const refreshExpiration = 3600 * 24 * 30
const accessExpiration  = 3600

/// Token ID generation

function generateIdToken(client, user) {

    const payload = {
        sub: user.id,  // Subject - the unique identifier of the user
        aud: client.clientId,  // Audience - the client ID
        iss: 'https://nomo.community.com',  // Issuer - your authorization server URL
        // exp: Math.floor(Date.now() / 1000) + (60 * 60),  // Expiration time - 1 hour
        iat: Math.floor(Date.now() / 1000),  // Issued at
        nonce: user.nonce,  // Nonce to mitigate replay attacks
        
    } | user.customClaims

    const options = { expiresIn: accessExpiration };
  
    const id_token = jwt.sign(payload, jwtSecretAccess, options);  // Sign the token with your secret key
    return id_token;
}

function verifyIdToken(token , done) {
    try {
      jwt.verify(token, jwtSecretAccess, {}, function(err,decoded) {
        if(err) return done(err)
        return done(null,decoded)
      })
    } catch (error) {
      return done(error)
    }
}

// Those are not really used. We just generate a long refresh token with an expiratiuon in the DB

// Generate a new refresh token
function generateRefreshToken(client,user) {
    const payload = {
      id_client: client.clientId,
      id: user.id,
      email: user.email
    };
  
    const options = { expiresIn: refreshExpiration };
  
    return jwt.sign(payload, jwtSecretRefresh, options);
  }
  
  // Verify a refresh token
  function verifyRefreshToken(token,done) {
    try {
      const decoded = jwt.verify(token, jwtSecretRefresh, function(err,decoded) {
        if(err) return done(err)
        return done(null,decoded)
      })
    } catch (error) {
        return done(error)
    }
  }
  
function generateAccessToken(client, user) {
    const token = utils.uid(256);  // Generate a random token
    db.accessTokens.save(token, client.clientId, user.id, function(err) {
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
exports.generateRefreshToken = generateRefreshToken
exports.verifyIdToken = verifyIdToken;
exports.verifyRefreshToken = verifyRefreshToken;
exports.generateAccessToken = generateAccessToken;
exports.generateAuthorizationCode = generateAuthorizationCode;