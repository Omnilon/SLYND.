const express = require('express');
const path = require('path');
const app = express();

// Middleware for parsing request bodies
app.use(express.urlencoded({ extended: true }));

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Set the view engine to ejs
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // point to your EJS templates directory

// GET route for the login page
app.get('/login', (req, res) => {
  res.render('login'); // renders the login.ejs file
});

// POST route for the login form submission
app.post('/login', (req, res) => {
  console.log('Login route hit, body:', req.body);
  res.send('Simple login route is working!');
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
