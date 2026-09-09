const express = require('express');
const cors = require('cors');
require('dotenv').config()
const db = require("./db");

const app = express();
const port = process.env.PORT || 5000;


app.use(express.json());
app.use(cors());



app.post('/users', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    // $1 and $2 are parameterized queries to prevent SQL Injection
    const newUser = await db.query(
      'INSERT INTO users (name, email,password) VALUES ($1, $2,$3) RETURNING *',
      [name, email,password]
    );
    res.status(201).json(newUser.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Server Error' });
  }
});

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Server Running  on port ${port}`);
});