/**
 * Module dependencies.
 */
var express = require('express')
  , passport = require('passport')
  , site = require('./site')
  , oauth2 = require('./oauth2')
  , user = require('./user')
  , client = require('./client')
  , util = require('util')
  , logger = require('morgan') 
  , cookieParser = require('cookie-parser')
  , bodyParser = require('body-parser')
  , session = require('express-session')
  , errorhandler = require('errorhandler')
  
  
// Express configuration
  
var app = express() ; //express.createServer();
app.set('view engine', 'ejs');
app.use(logger('combined')); // app.use(express.logger());
app.use(cookieParser());//app.use(express.cookieParser());
//app.use(express.bodyParser());
// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }))
// parse application/json
app.use(bodyParser.json())
//app.use(express.session({ secret: 'keyboard cat' }));
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true }
}))
/*
app.use(function(req, res, next) {
  console.log('-- session --');
  console.dir(req.session);
  //console.log(util.inspect(req.session, true, 3));
  console.log('-------------');
  next()
});
*/
app.use(passport.initialize());
app.use(passport.session());
//app.use(app.router);
//app.use(express.errorHandler({ dumpExceptions: true, showStack: true }));
app.use(errorhandler({ dumpExceptions: true, showStack: true }));

// Passport configuration

require('./auth');


app.get('/', site.index);
app.get('/login', site.loginForm);
app.post('/login', site.login);
app.get('/logout', site.logout);
app.get('/account', site.account);

app.get('/dialog/authorize', oauth2.authorization);
app.post('/dialog/authorize/decision', oauth2.decision);
app.post('/oauth/token', oauth2.token);
app.post('/oauth/refresh', oauth2.refresh);
app.post('/token/claims', oauth2.claims);
app.post('/token/verify', oauth2.verify);

app.get('/api/userinfo', user.info);
app.get('/api/clientinfo', client.info);

app.listen(3000);
