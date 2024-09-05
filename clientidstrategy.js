const passport = require('passport-strategy');
const util = require('util');

// Define the ClientIDStrategy constructor
function ClientIDStrategy(verify) {
  if (!verify) {
    throw new TypeError('ClientIDStrategy requires a verify callback');
  }

  passport.Strategy.call(this);
  this.name = 'client-id'; // Name your strategy
  this._verify = verify;
}

// Inherit from `passport.Strategy`
util.inherits(ClientIDStrategy, passport.Strategy);

// Implement the authenticate function
ClientIDStrategy.prototype.authenticate = function(req) {
  const clientId = req.body.client_id || req.query.client_id; // Get clientId from body or query

  if (!clientId) {
    return this.fail({ message: 'Missing client_id' }, 400);
  }

  const self = this;
  // Call the verify function to authenticate the clientId
  this._verify(clientId, function(err, client, info) {
    if (err) {
      return self.error(err);
    }
    if (!client) {
      return self.fail(info || { message: 'Invalid client_id' }, 400);
    }
    self.success(client, info);
  });
};

// Export the strategy
module.exports = ClientIDStrategy;
