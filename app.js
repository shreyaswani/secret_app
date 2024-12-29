require('dotenv').config();
const path = require('path');

const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const firebase = require("firebase");

const app = express();

app.use(express.static("public"));
app.use(express.static(path.join(__dirname, 'public')));
app.set('views', path.join(__dirname, 'views'));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

const firebaseConfig = {
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    databaseURL: process.env.FIREBASE_DATABASE_URL,
    projectId: process.env.FIREBASE_PROJECT_ID,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.FIREBASE_APP_ID,
    measurementId: process.env.FIREBASE_MEASUREMENT_URL
  };

firebase.initializeApp(firebaseConfig);
const db = firebase.database(); 
const auth = firebase.auth();

function checkAuth(req, res, next) {
    const user = auth.currentUser;
    if (user) {
      next();
    } else {
      res.redirect("/login");
    }
  }

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.post("/register", async (req, res) => {
    const { email, password } = req.body;
    try {
      await firebase.auth().createUserWithEmailAndPassword(email, password);
      res.redirect("/secret?success=Registration successful.");
    } catch (error) {
      res.redirect(`/register?error=${encodeURIComponent(error.message)}`);
    }
  });

  app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    try {
      await firebase.auth().signInWithEmailAndPassword(email, password);
      res.redirect("/secret?success=Login successful.");
    } catch (error) {
      res.redirect(`/login?error=Check credentials and try again`);
    }
  });

  app.get("/secret", checkAuth, async (req, res) => {
    try {
      const secretsSnapshot = await db.ref("secrets").once("value");
      const secretsData = secretsSnapshot.val();
  
      const secrets = secretsData
        ? Object.values(secretsData).map((secretObj) => secretObj.secret)
        : [];
      res.render("secrets", { secrets });
    } catch (err) {
      res.status(500).send("error-An error occurred while fetching secrets.");
    }
  });
  
  app.get("/submit", checkAuth, function (req, res) {
    res.render("submit");
  });

app.post("/submit", async (req, res) => {
  const { secret } = req.body;

  if (secret && secret.trim() !== "") {
    try {
      await db.ref("secrets").push({ secret, createdAt: new Date().toISOString() });
      res.redirect("/secret");
    } catch (err) {
      res.status(500).send("error=An error occurred while saving your secret.");
    }
  } else {
    res.send("error=Please enter a valid secret.");
  }
});
app.get("/logout", async (req, res) => {
    try {
      await firebase.auth().signOut();
      res.redirect("/login?success=Logged out successfully.");
    } catch (error) {
      res.redirect(`/secret?error=An error occured.}`);
    }
  });

app.get("/submit", function (req, res) {
  res.render("submit");
});

app.listen(3000, function () {
  console.log("Server is running on port no. 3000");
});
