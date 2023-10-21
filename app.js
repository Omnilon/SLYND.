require('dotenv').config();

const helmet = require('helmet');
const express = require('express');
const path = require('path');
const { MongoClient, ObjectId } = require('mongodb');
const session = require('express-session');
const passport = require('passport');
const bcrypt = require('bcrypt');
const LocalStrategy = require('passport-local').Strategy;
const MongoStore = require('connect-mongo');

const winston = require('winston');

const logger = winston.createLogger({
  level: 'info', // Log only if info level or higher
  format: winston.format.json(), // Log format
  defaultMeta: { service: 'user-service' }, // Optional metadata
  transports: [
    // - Write all logs error (and below) to `error.log`.
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    // - Write all logs to `combined.log`.
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

// If we're not in production, log to the `console` with the format:
// `${info.level}: ${info.message} JSON.stringify({ ...rest }) `
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

logger.info('Hello, Winston!');


const uri = process.env.MONGO_URI;
const dbName = 'SLYND';




const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});




async function main() {
  try {
    await client.connect();
    console.log('Connected to MongoDB');
    const db = client.db(dbName);
    const collection = db.collection('registration');




    const app = express();

    app.set('view engine', 'ejs');
    app.set('views', path.join(__dirname, 'views')); // Assuming your EJS templates are in a "views" directory in your project root
   

    app.use(express.static(path.join(__dirname, 'public')));

    app.use(express.urlencoded({ extended: false }));

    app.use(helmet());
    app.use(session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        store: MongoStore.create({
          client: client, // using the existing MongoDB client
          dbName: dbName, // the name of the database to store sessions
          collectionName: 'sessions', // the name of the collection to store sessions
          ttl: 14 * 24 * 60 * 60, // = 14 days. Default
          autoRemove: 'native', // Default
        }),
        cookie: {
            secure: false, // Set to true only in production
          httpOnly: false,
          maxAge: 14 * 24 * 60 * 60 * 1000, // = 14 days
        }
      }));  
    app.use(passport.initialize());
    app.use(passport.session());
     
    passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
      try {                              
        const user = await collection.findOne({ email: email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
          return done(null, false, { message: 'Incorrect email or password.' });
        }
        return done(null, user);
      } catch (e) {
        return done(e);
      }
    }));

    passport.serializeUser((user, done) => done(null, user._id));
    passport.deserializeUser((id, done) => {
      collection.findOne({ _id: new ObjectId(id) }, (err, user) => done(err, user));
    });
   

    app.use(require('connect-flash')());
    app.use((req, res, next) => {
        logger.info(`${req.method} ${req.url}`);
        next();
      });
    app.use((req, res, next) => {
        res.locals.messages = req.flash();
        next();
      });

      app.get('/login', function(req, res) {
        res.render('login');
    });

    app.get('/register', function(req, res) {
      res.render('register');
  });

  app.post('/register', async (req, res) => {
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      const user = { username: req.body.username, email: req.body.email, password: hashedPassword };
      await collection.insertOne(user);
      res.redirect('/login');
    } catch (error) {
      console.error(error);
      res.redirect('/register');
    }
  });

  app.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: 'Invalid username or password.',
successFlash: 'Welcome!'
}));

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/login');
});

app.get('/dashboard', function(req, res) {
  if(req.isAuthenticated()) {
      res.render('dashboard', { user: req.user });
  } else {
      res.redirect('/login');
  }
});

// Catch 404 and forward to error handler
app.use((req, res, next) => {
    const err = new Error('Not Found');
    err.status = 404;
    next(err);
  });
 
  // Error handler
  app.use((err, req, res, next) => {
    // Log the error
    logger.error(`${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
 
    // Set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};
 
    // Render the error page
    res.status(err.status || 500);
    res.render('error', { env: req.app.get('env') }); // pass the environment to the EJS template
  });
 

  process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Application specific logging, throwing an error, or other logic here
  });
 


   const PORT = process.env.PORT || 3000;
    const server = app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });

  // Graceful shutdown logic
    function gracefulShutdown() {
      console.log('Shutting down gracefully...');
      server.close(() => {
        console.log('Closed out remaining connections.');
        client.close(false, () => {
          console.log('MongoDB connection closed.');
          process.exit(0);
        });
      });
    }




    process.on('SIGTERM', gracefulShutdown);
    process.on('SIGINT', gracefulShutdown);




  } catch (err) {
    console.error('Error connecting to MongoDB', err);
    process.exit(1);
  }
}




main().catch(console.error);