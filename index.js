const express = require('express');
const cors = require('cors');
require('dotenv').config()
const cookieParser = require("cookie-parser");
const db = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");




const app = express();
app.use(cookieParser());


const port = process.env.PORT || 5000;


app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

// create users api here

app.post("/users", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      error: "Name, email and password are required",
    });
  }

  try {
    
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await db.query(
      `INSERT INTO users (name, email, password)
       VALUES ($1, $2, $3)
       RETURNING id, name, email `,
      [name, email, hashedPassword]
    );

    res.status(201).json({
      message: "User created successfully",
      user: newUser.rows[0],
    });
  } catch (err) {
    console.error("Create user error:", err.message);

   
    if (err.code === "23505") {
      return res.status(409).json({
        error: "Email already exists",
      });
    }

    res.status(500).json({
      error: "Server Error",
    });
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



// login users

// app.post("/users", async (req, res) => {
//   const { name, email, password } = req.body;

//   // Validation
//   if (!name || !email || !password) {
//     return res.status(400).json({
//       error: "Name, email and password are required",
//     });
//   }

//   try {
//     // Check existing email
//     const existingUser = await db.query(
//       "SELECT id FROM users WHERE email = $1",
//       [email]
//     );

//     if (existingUser.rows.length > 0) {
//       return res.status(409).json({
//         error: "Email already exists",
//       });
//     }

//     // Hash password
//     const hashedPassword = await bcrypt.hash(password, 10);

//     // Insert user
//     const newUser = await db.query(
//       `INSERT INTO users (name, email, password)
//        VALUES ($1, $2, $3)
//        RETURNING id, name, email`,
//       [name, email, hashedPassword]
//     );

//     res.status(201).json({
//       message: "User created successfully",
//       user: newUser.rows[0],
//     });

//   } catch (err) {
//     console.error("Create user error:", err.message);

//     res.status(500).json({
//       error: "Server Error",
//     });
//   }
// });




app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Validation
  if (!email || !password) {
    return res.status(400).json({
      error: "Email and password are required",
    });
  }

  try {
    // Find user
    const result = await db.query(
      `SELECT id, name, email, password
       FROM users
       WHERE email = $1`,
      [email]
    );

    const user = result.rows[0];

    // User not found
    if (!user) {
      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(
      password,
      user.password
    );

    if (!isPasswordValid) {
      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    // Check JWT secret
    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET is missing");

      return res.status(500).json({
        error: "JWT secret is not configured",
      });
    }

    // Create JWT
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    // Store JWT in cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 60 * 60 * 1000,
    });

    // Response
    res.status(200).json({
      message: "Login successful",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });

  } catch (err) {
    console.error("Login error:", err.message);

    res.status(500).json({
      error: "Server Error",
    });
  }
});



app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Server Running  on port ${port}`);
});