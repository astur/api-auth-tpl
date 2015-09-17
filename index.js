var express = require('express');
var app = express();
var auth = require('basic-auth');
var hat = require('hat');

var User = require('./model');

//Middlewares

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

function getToken(req, res, next) {
    var u = auth(req);

    User.findOne({username: u.name}, function(err, user){
        if(err) {return next(err);}
        if (!user || !user.checkPassword(u.pass)) {
            return res.status(401).json({error: 'Bad username or password'});
        }
        return res.json({token: user.token, message: 'User found'});
    });
}

function createUser(req, res, next) {
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
}

//App

app.get('/', function(req, res) {
    res.end('Hello world!');
});

app.get('/auth', checkCredentials, getToken);

app.get('/register', checkCredentials, createUser);

app.all('/api', tokenAuth, function(req, res) {
    return res.json({user: req.user.username});
});

//Server

app.listen(3000, function () {
  console.log('Listening at port 3000');
});