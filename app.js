//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: "Thisisthesecret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());
//use passport when dealing with session



mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser:true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
// hash and salt passwords and save users to db
userSchema.plugin(findOrCreate);



// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);


passport.use(User.createStrategy());
// creates an authentication mechanism

passport.serializeUser(function(user, done) {
    done(null, user.id);
   // where is this user.id going? Are we supposed to access this anywhere?
});
//serializeUser determines which data of the user object should be stored in the session.


passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});
// cracks the fortune cookie, allows passport to discover is inside the cookie or session

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

     User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res){
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile'] })
  //initiate passport to authenticate using the google Strategy which we set up
  // exchanges of authentications info initiates
  //the 2nd parameters tells google we want the users's userProfile once its authenticated
  // once google authenticated Successfully, google will call the callback, and then the callbackURL
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: '/login' }),
  // authenticates the user locally using the google strategy and checks they previously authenticated through google
  //, authenticating locally sets up the cookies and session
  function(req, res) {

    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  }
);


app.get("/login", function(req, res){
  res.render("login");
});


app.get("/register", function(req, res){
  res.render("register");
});


app.get("/secrets", function(req, res){

  User.find({"secret": {$ne:null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    }else{
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
  // if (req.isAuthenticated()){
  //   // deserializes and checks if user is authenticated
  //   res.render("secrets");
  // }else{
  //   res.redirect("/login");
  // }
});
app.get("/logout", function(req, res){
  req.logout();
  //unauthenticate user and deletes cookie
  res.redirect("/");
});


app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    // deserializes and checks if user is authenticated
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});





// POST

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
// passport saves users details into req var when we initiate a login session/cookie(when we login)
    User.findById(req.user.id, function(err, foundUser){
      if(err){
        console.log(err);
      } else {
        if(foundUser){
          foundUser.secret = submittedSecret;
          foundUser.save(function(){
            //saves to database
            res.redirect("/secrets");
          });
        }
      }
    });
});

app.post("/register", function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    //passport-local-mongoose allows us to register/create user simply
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req, res, function(){
        //authenticates the user
        // authentication is what actually logs in the user
        // allowing it access particular info that requires authentication
        // if authentication succeeds, a session will be established and maintained via a cookie set in the user's browser
        // inside the cookie the content has meaning to our server(localhost) that the current user is authenticated
        //serializes user/ creates that fortune cookie
        //call back is called once authentication succeeds
        res.redirect("/secrets");
      });
    }
  });
});
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  // // call function runs after the previous is completed
  // // Store hash in your password DB.
  // const newUser = new User({
  //   email: req.body.username,
  //   password: hash
  // });
  //
  // newUser.save(function(err){
  //   if(err){
  //     console.log(err);
  //   }else{
  //     res.render("secrets");
  //   }
  // });





app.post("/login", function(req, res){
    const user = new User({
      username: req.body.username,
      password: req.body.password,
    });

    req.login(user, function(err){
      //checks if user exists in data base
      if (err){
        console.log(err);
      } else{
        passport.authenticate("local")(req, res, function(){
          res.redirect("/secrets");
        });
      }
    });
    //passport method

});
  // const username = req.body.username;
  // const password = req.body.password ;
  //
  // User.findOne({email: username},  function(err, foundUser){
  //   if (err){
  //     console.log(err);
  //   } else{
  //     if (foundUser){
  //       bcrypt.compare(password, foundUser.password, function(err, result) {
  //     // result is a boolean
  //         if (result === true){
  //           res.render("secrets");
  //           console.log("accessed");
  //       }
  //     });
  //     }
  //   }
  // });



app.listen(3000, function() {
    console.log("Server started on port 3000.");
});
