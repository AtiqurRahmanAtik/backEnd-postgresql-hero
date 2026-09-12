const express = require('express');
const cors = require('cors');
require('dotenv').config()
const db = require("./db");

const app = express();
const port = process.env.PORT || 5000;


app.use(express.json());
app.use(cors());


// create users api here
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


//get all users api here
app.get("/users", async(req,res)=>{


  try{

    const result = await db.query("SELECT id,name, email,password FROM users ORDER BY id ASC");

    res.status(200).json({message:"get all users", users:result.rows})
  }

  catch (error) {
    console.error("Get users error:", error.message);

    res.status(500).json({
      error: "Server error while fetching users",
    });
  }
  
})


// single user api here
app.get("/users/:id", async(req,res)=>{
  const {id} = req.params;

  try{

    const result = await db.query(`SELECT id,name,email,password FROM users WHERE id=$1`,[id]);

     if (result.rows.length === 0) {
      return res.status(404).json({
        error: "User not found",
      });
    }


    res.status(200).json({message:"get single user api ", user:result.rows[0]})
  }
  catch (error) {
    console.error("Get user error:", error.message);

    res.status(500).json({
      error: "Server error while fetching user",
    });
  }
})


// update single user data
app.put("/users/:id", async (req,res)=>{
  const {id} = req.params;
  const {name,email,password} = req.body;

   if (!name || !email || !password)  {
    return res.status(400).json({
      error: "Name and email are required",
    });
  }

  try{


    const result = await db.query(
      `UPDATE users 
      SET name= $1, 
      email = $2 ,
      password = $3
      
     WHERE id = $4
       RETURNING id, name, email, password`,
      [name, email, password, id]
     
    )


     if (result.rows.length === 0) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    res.status(200).json({
      message: "User updated successfully",
      user: result.rows[0],
    });
    // res.status(200).json({message:"update successfully",data:result.rows[0]})

  }
  catch(err){
     console.error("Get users error:", err.message);

    res.status(500).json({
      error: "Server error while fetching users",
    });
  }
})


app.delete("/users/:id", async(req,res)=>{
  const {id} = req.params;

  try{

    const result = await db.query(`
      DELETE FROM users 
      WHERE id = $1 
      RETURNING id,name,email,password`,
      [id]);

    if(result.rows.length === 0){
       return res.status(404).json({
        error: "User not found",});
    }

    res.status(200).json({
      message: "User deleted successfully",
      user: result.rows[0]
    });

  }
   catch (error) {
    console.error("Delete user error:", error.message);

    res.status(500).json({
      error: "Server error while deleting user",
    });
  }
})




app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Server Running  on port ${port}`);
});