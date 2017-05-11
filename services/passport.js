const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');


//Setup options for local strategy
const localOptions = { 
    usernameField: 'email'
};

//Create local strategy
const localLogin = new LocalStrategy(localOptions, function(email, password, done){

    //Verify email and password
    //Call 'done' with the 'user' if it is the correct 'email' and 'password'
    //Otherwise, call 'done' with false
    User.findOne({email: email}, function(err, user){
        if(err) { return done(err); }

        if(!user){ return done(null, false); }

        user.comparePassword(password, function(err, isMatch){
            if(err) { return done(err); }

            if(!isMatch) { return done(null, false); }

            return done(null, user);
        });

    });

});

//Setup options for JWT Strategy
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: config.secret
};

//Create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done){

    //See if the user ID in the payload exists in our database
    //If it does, call 'done' with it
    //Otherwise, call 'done' without a user object

    User.findById(payload.sub, function(err, user){
        if(err) { return done(err); }

        if(user){
            done(null, user);
        }
        else{
            done(null, false);
        }
    });

});

passport.use(jwtLogin);
passport.use(localLogin);