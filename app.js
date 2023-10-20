const express = require('express');
const app = express();

app.get('/login', (req, res) => {
  res.send('Login page');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

app.post('/login', (req, res) => {
  console.log('Login route hit, body:', req.body);
  res.send('Simple login route is working!');
});
