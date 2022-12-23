//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const findOrCreate = require('mongoose-findorcreate');
// const encrypt = require('mongoose-encryption');
// const becrypt = require('bcrypt');
// const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
app.use(express.static(__dirname + '/public'));
app.use(bodyParser.urlencoded({extended: true}));
app.set('view engine', 'ejs');

app.use(session({
    secret:"ItsMySecret.",
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize());
app.use(passport.session()); //this is used to create a cookie and store the user info in it

mongoose.set("strictQuery", true);
mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser: true});
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    //for google authentication
    googleId: String,
    secret: String
});

//this is a level 2 security using a key
//hacker can still be able to see through the .env by prevopus commits
//so we need to use a level 3 & 4 security i.e. hashing and salting

// const secret = process.env.SECRET;
//ecnrypt the password before creatong the user model

// userSchema.plugin(encrypt,{secret:secret,encryptedFields:['password']})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.displayName });
    });
});//this is used to create a cookie and store the user info in it
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
});//this is used to decrypt the cookie and get the user info from it
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/secrets',
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//get routes
app.get('/',(req,res)=>{
    res.render('home');
});
app.get('/auth/google', passport.authenticate('google', {
    scope: ['profile']
}));
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});
app.get('/login',(req,res)=>{
    res.render('login');
});
app.get('/register',(req,res)=>{
    res.render('register');
});
app.get('/logout', function(req, res, next) {
    req.logout(function(err) {//this is used to destroy the cookie
      if (err) { return next(err); }
      res.redirect('/');
    });
});
app.get('/secrets',(req,res)=>{
    User.find({'secret':{$ne:null}},(err,foundUsers)=>{
        if(err){
            console.log(err);
        }else{
            if(foundUsers){
                res.render('secrets',{usersWithSecrets:foundUsers});
            }
        }
    })
})
app.get('/submit',(req,res)=>{
    if(req.isAuthenticated()){
        res.render('submit');
    }else{
        res.redirect('/login');
    }
})

//post routes
app.post('/submit',(req,res)=>{
    const submittedSecret = req.body.secret
    console.log(req.user);
    User.findById(req.user.id,(err,foundUser)=>{
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(()=>{
                    res.redirect('/secrets');
                })
            }
        }
    })
})
app.post('/register',(req,res)=>{
    //Level4 security i.e. passport
    User.register({username:req.body.username},req.body.password,(err,user)=>{
        if(err){
            console.log(err);
            res.redirect('/register');
        }else{
            passport.authenticate("local")(req,res,()=>{
                res.redirect('/secrets');
            })
        }
    })

    //level 3 security i.e. hash
    // becrypt.hash(req.body.password, saltRounds,(err, hash)=>{
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash //level 3+4 security i.e. hash+salt
    //     })
    //     newUser.save((err)=>{
    //         if(err){
    //             console.log(err);
    //         }else{
    //             res.render('secrets');
    //         }
    //     })
    // })
});
app.post('/login',(req,res)=>{
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user,(err)=>{
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req,res,()=>{
                res.redirect('/secrets');
            })
        }
    })

    // const username = req.body.username;
    // const password =req.body.password;
    // User.findOne({email:username},(err,foundUser)=>{
    //     if(!err){
    //         if(foundUser){
    //             becrypt.compare(password, foundUser.password, function(err, result){
    //                 if(result === true){
    //                     res.render('secrets');
    //                 }
    //             })
    //         }
    //     }else{
    //         console.log(err);
    //     }
    // })
});



app.listen(3000,()=>{
    console.log("Server started on port 3000");
});