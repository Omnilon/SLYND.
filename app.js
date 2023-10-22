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
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'user-service' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
    
  }));
}

logger.info('Starting application');

const uri = process.env.MONGO_URI;
const dbName = 'SLYND';
const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

async function main() {
  try {
    await client.connect();
    logger.info('Connected to MongoDB');
    const db = client.db(dbName);
    const collection = db.collection('registration');

    const app = express();

    app.set('view engine', 'ejs');
    app.set('views', path.join(__dirname, 'views'));

    app.use(express.static(path.join(__dirname, 'public')));
    app.use(express.urlencoded({ extended: false }));
    app.use(helmet());
    app.use(session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: true,
      store: MongoStore.create({
        client: client,
        dbName: dbName,
        collectionName: 'sessions',
        ttl: 14 * 24 * 60 * 60,
        autoRemove: 'native',
      }),
      cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 14 * 24 * 60 * 60 * 1000,
      }
    }));
    app.use(passport.initialize());
    app.use(passport.session());

    passport.use(new LocalStrategy({ usernameField: 'username' }, async (username, password, done) => {
      try {
        const user = await collection.findOne({ username: username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
          logger.warn('Authentication failed: Incorrect username or password');
          return done(null, false, { message: 'Incorrect username or password.' });
        }
        logger.info('Authentication successful');
        return done(null, user);
      } catch (e) {
        logger.error('Error in LocalStrategy', e);
        return done(e);
      }
    }));

    app.use(require('connect-flash')());
    app.use((req, res, next) => {
      logger.info(`Request received: ${req.method} ${req.url}`);
      next();
    });
    app.use((req, res, next) => {
      res.locals.messages = req.flash();
      next();
    });

    passport.serializeUser((user, done) => {
      logger.info('Serializing user');
      done(null, user._id);
    });

    passport.deserializeUser((id, done) => {
      logger.info(`Deserializing user with id: ${id}`);
      collection.findOne({ _id: new ObjectId(id) }, (err, user) => {
          if (err) {
              logger.error('Error in deserializeUser', err);
              return done(err, null);
          }
          if (!user) {
              logger.error(`No user found with id: ${id}`);
              return done(null, false);
          }
          logger.info(`User deserialized: ${user.username}`);
          return done(null, user);
      });
  });
  
  

    // Define your routes here

    app.get('/', (req, res) => {
      logger.info('GET /');
      res.render('register');
    });
    

    app.get('/login', (req, res) => { 
        logger.info('GET /login');
        res.render('login'); 
    });

    app.get('/register', (req, res) => {
        logger.info('GET /register');
        res.render('register'); 
    });

    app.get('/dashboard', (req, res) => {
      if(req.isAuthenticated()) {
          res.send(`User is authenticated, username: ${req.user.username}`);
      } else {
          res.redirect('/login');
      }
  });
  

    app.post('/register', async (req, res) => {
        logger.info('POST /register');
        try {
            const hashedPassword = await bcrypt.hash(req.body.password, 10);
            const user = { username: req.body.username, email: req.body.email, password: hashedPassword };
            await collection.insertOne(user);
            logger.info('User registered successfully');
            res.redirect('/login');
        } catch (error) {
            logger.error('Registration error', error);
            res.redirect('/register');
        }
    });

    app.post('/login', (req, res, next) => {
        logger.info('POST /login');
        passport.authenticate('local', (err, user, info) => {
            if (err) { 
                logger.error('Error in passport authentication', err);
                return next(err); 
            }
            if (!user) { 
                logger.warn('Authentication failed', info);
                return res.redirect('/login'); 
            }
            req.logIn(user, function(err) {
                if (err) { 
                    logger.error('Error in logIn method', err);
                    return next(err); 
                }
                logger.info('User logged in successfully');
                return res.redirect('/dashboard');
            });
        })(req, res, next);
    });

    app.get('/logout', (req, res) => {
        logger.info('GET /logout');
        req.logout();
        logger.info('User logged out successfully');
        res.redirect('/login');
    });

    // Error handlers
    app.use((req, res, next) => {
      const err = new Error('Not Found');
      err.status = 404;
      next(err);
    });

    app.use((err, req, res, next) => {
      // Log the error
      logger.error(`${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
    
      // Set locals, only providing error in development
      res.locals.message = err.message;
      res.locals.error = req.app.get('env') === 'development' ? err : {};
    
      // Set the status and render the error page
      res.status(err.status || 500);
      res.render('error', { env: process.env.NODE_ENV }); // pass the environment to the EJS template
    });
    

    const PORT = process.env.PORT || 3000;
    const server = app.listen(PORT, () => {
      logger.info(`Server is running on port ${PORT}`);
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    });

    process.on('SIGTERM', gracefulShutdown);
    process.on('SIGINT', gracefulShutdown);

    function gracefulShutdown() {
      logger.info('Shutting down gracefully');
      server.close(() => {
        logger.info('Closed out remaining connections');
        client.close(false, () => {
          logger.info('MongoDB connection closed');
          process.exit(0);
        });
      });
    }

  } catch (err) {
    logger.error('Error connecting to MongoDB', err);
    process.exit(1);
  }
}

main().catch(console.error);
