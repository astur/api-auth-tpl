var express = require('express');
var app = express();
var mongoose = require('mongoose');
var auth = require('basic-auth');
var crypto = require('crypto');
var hat = require('hat');

mongoose.connect('mongodb://localhost/test', function(err){
    if(err){console.log('Failed connection to database');}
});

var schema = new mongoose.Schema({
  username: {
    type: String,
    unique: true,
    required: true
  },
  hash: {
    type: String,
    required: true
  },
  salt: {
    type: String,
    required: true
  },
  token: {
    type: String,
    required: true
  }
});

schema.methods.encryptPassword = function(password) {
  return crypto.createHmac('sha1', this.salt).update(password).digest('hex');
};

schema.virtual('password')
  .set(function(password) {
    this._plainPassword = password;
    this.salt = Math.random() + '';
    this.hash = this.encryptPassword(password);
  })
  .get(function() { return this._plainPassword; });


schema.methods.checkPassword = function(password) {
  return this.encryptPassword(password) === this.hash;
};

var User = mongoose.model('User', schema);

function checkCredentials(req, res, next) {
    var u = auth(req);
    if(!u || u.pass === ''){
        return res.status(401).json({error: 'HTTP Authorization Required'});
    }
    next();
}

function tokenAuth(req, res, next) {
    var t = req.query.token;
    if (!t) {
        return res.status(403).json({error: 'Token Authorization Required'});
    }
    User.findOne({token: t}, function(err, user){
        if(err) {return next(err);}
        if(!user) {return res.status(403).json({error: 'Bad Token'});}
        req.user = user;
        next();
    });
}

app.get('/', function(req, res) {
    res.end('Hello world!');
});

app.get('/auth', checkCredentials, function(req, res, next) {
    var u = auth(req);

    User.findOne({username: u.name}, function(err, user){
        if(err) {return next(err);}
        if (!user || !user.checkPassword(u.pass)) {
            return res.status(401).json({error: 'Bad username or password'});
        }
        return res.json({token: user.token, message: 'User found'});
    });
});

app.get('/register', checkCredentials, function(req, res, next) {
    var u = auth(req);

    User.findOne({username: u.name}, function(err, user){
        if(err) {return next(err);}
        if (!user) {
            user = new User({username: u.name, password: u.pass, token: hat()});
            user.save(function(err){
                if(err) {return next(err);}
                return res.json({token: user.token, message: 'User created'});
            });
        } else {
            return res.json({error: 'User already exists'});
        }
    });
});

app.all('/api', tokenAuth, function(req, res) {
    return res.json({user: req.user.username});
});

app.listen(3000, function () {
  console.log('Listening at port 3000');
});