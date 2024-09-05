const jwt = require('jsonwebtoken');

function verifyAccessToken(token, done) {
    // Look up the access token in the database
    db.accessTokens.find(token, function(err, accessToken) {
      if (err) { return done(err); }
      if (!accessToken) { return done(null, false); }
  
      // Check if the token has expired
      const now = Math.floor(Date.now() / 1000); // current time in seconds
      if (accessToken.expiresAt && accessToken.expiresAt < now) {
        return done(null, false, { message: 'Access token has expired' });
      }
  
      // If the token is valid, return the associated user or client
      if (accessToken.userId) {
        db.users.find(accessToken.userId, function(err, user) {
          if (err) { return done(err); }
          if (!user) { return done(null, false); }
          return done(null, user); // token is valid, return the user
        });
      } else if (accessToken.clientId) {
        db.clients.findByClientId(accessToken.clientId, function(err, client) {
          if (err) { return done(err); }
          if (!client) { return done(null, false); }
          return done(null, client); // token is valid, return the client
        });
      } else {
        return done(null, false);
      }
    });
  }




// Function to retrieve the signing key
const client = jwksClient({
  jwksUri: process.env.JWKS_URI // URL to your JWKS (JSON Web Key Set)
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, function(err, key) {
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

function verifyIdToken(idToken, done) {
  // Decode and verify the JWT
  jwt.verify(idToken, getKey, {
    algorithms: ['RS256'], // Specify your signing algorithm
    audience: process.env.CLIENT_ID, // Expected audience (client ID)
    issuer: process.env.ISSUER // Expected issuer
  }, function(err, decoded) {
    if (err) {
      return done(null, false, { message: 'Invalid ID token' });
    }

    // Check expiration and other claims
    const now = Math.floor(Date.now() / 1000);
    if (decoded.exp < now) {
      return done(null, false, { message: 'ID token has expired' });
    }

    // If valid, return the decoded token
    done(null, decoded);
  });
}

  
