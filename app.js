require('dotenv').config();
const express = require('express');
const path = require('path');
const { MongoClient } = require('mongodb');
const session = require('express-session');
const passport = require('passport');
const bcrypt = require('bcrypt');
const LocalStrategy = require('passport-local').Strategy;
const MongoStore = require('connect-mongo');

const uri = process.env.MONGO_URI;
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

async function main() {
  await client.connect();
  const db = client.db('SLYND');
  const usersCollection = db.collection('users');

  const app = express();
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  app.use(express.static(path.join(__dirname, 'public')));
  app.use(express.urlencoded({ extended: false }));

  const sessionStore = MongoStore.create({ client: client, dbName: 'SLYND', collectionName: 'sessions' });
  app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    store: sessionStore
  }));

  app.use(passport.initialize());
  app.use(passport.session());

  passport.use(new LocalStrategy(
    async (username, password, done) => {
      const user = await usersCollection.findOne({ username });
      if (user && await bcrypt.compare(password, user.password)) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect credentials' });
      }
    }
  ));

  passport.serializeUser((user, done) => done(null, user._id));
  passport.deserializeUser((id, done) => {
    usersCollection.findOne({ _id: id }, (err, user) => {
      done(err, user);
    });
  });

  // Routes: simplified for brevity
  app.get('/', (req, res) => res.render('register'));

  app.get('/register', (req, res) => {
    logger.info('GET /register');
    res.render('register'); // Make sure 'register.ejs' exists in your 'views' directory
});


  app.get('/dashboard', (req, res) => {
    if(req.isAuthenticated()) {
      res.render('dashboard', { user: req.user });
    } else {
      res.redirect('/login');
    }
  });

  app.post('/register', async (req, res) => {
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      const user = { username: req.body.username, email: req.body.email, password: hashedPassword };
      await usersCollection.insertOne(user);
      res.redirect('/login');
    } catch (error) {
      console.error('Registration error', error);
      res.redirect('/register');
    }
  });
  
  // Login routes
  app.get('/login', (req, res) => {
    if(req.isAuthenticated()) {
      res.redirect('/dashboard');
    } else {
      res.render('login');
    }
  });
  
  app.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
  }));
  
  // Logout route
  app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/login');
  });

  // ... other routes ...

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

main().catch(console.error);
