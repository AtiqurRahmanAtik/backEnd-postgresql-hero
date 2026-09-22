const authenticateUser = require("./middleware/auth");
const authorizeRoles = require("./middleware/authorize");
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
// middleware api


app.get("/me", authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(
      `SELECT id, name, email, role, photo
       FROM users
       WHERE id = $1`,
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    return res.status(200).json({
      user: result.rows[0],
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Failed to fetch user",
    });
  }
});





// User Registration api
app.post("/users", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      error: "Name, email and password are required",
    });
  }

  try {
    // Check existing email
    const existingUser = await db.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        error: "Email already exists",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Default role = User
    const newUser = await db.query(
      `INSERT INTO users (name, email, password, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, email, role`,
      [name, email, hashedPassword, "User"]
    );

    res.status(201).json({
      message: "User created successfully",
      user: newUser.rows[0],
    });
  } catch (err) {
    console.error("Create user error:", err.message);

    res.status(500).json({
      error: "Server Error",
    });
  }
});


//get all users api here
app.get("/users", async(req,res)=>{


  try{

    const result = await db.query("SELECT id,name, email,password,role FROM users ORDER BY id ASC");

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





// normanl user login 
// {
  
//    "email": "tanvirhllekdtir80@gmail.com",
//    "password": "atik3333"

// }

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  console.log("result : ", email)

  if (!email || !password) {
    return res.status(400).json({
      error: "Email and password are required",
    });
  }

  if (!process.env.JWT_SECRET) {
    return res.status(500).json({
      error: "JWT secret is not configured",
    });
  }

  try {
    // Find user
    const result = await db.query(
      `SELECT id, name, email, password, role
       FROM users
       WHERE email = $1`,
      [email]
    );

    const user = result.rows[0];

    console.log("data : ", user)

    if (!user) {
      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    // Compare password
    const isPasswordValid = await bcrypt.compare(
      password,
      user.password
    );

    if (!isPasswordValid) {
      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    // Create JWT
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    // Store JWT in HttpOnly cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: false, // true in production with HTTPS
      sameSite: "lax",
      maxAge: 60 * 60 * 1000,
    });

    res.status(200).json({
      message: "Login successful",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("Login error:", err.message);

    res.status(500).json({
      error: "Server Error",
    });
  }
});


// Logout api
app.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  maxAge: 60 * 60 * 1000,
    
    
  });

  res.status(200).json({
    message: "Logout successful",
  });
});




// user Dashboard
app.get(
  "/user-dashboard",
  authenticateUser,
  authorizeRoles("User"),
  (req, res) => {
    res.status(200).json({
      message: "Welcome to User Dashboard",
      user: req.user,
    });
  }
);




// {
 
//              "name": "admin",
//             "email": "admin@gmail.com",
//             "password": "atik1234"
            
            
// }
// Create Admin Dashboard
// app.post("/admin/create", async (req, res) => {
//   const { name, email, password } = req.body;

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

//     // Create Admin
//     const newAdmin = await db.query(
//       `INSERT INTO users (name, email, password, role)
//        VALUES ($1, $2, $3, $4)
//        RETURNING id, name, email, role`,
//       [name, email, hashedPassword, "Admin"]
//     );

//     res.status(201).json({
//       message: "Admin created successfully",
//       user: newAdmin.rows[0],
//     });
//   } catch (error) {
//     console.error("Admin create error:", error.message);

//     res.status(500).json({
//       error: "Server Error",
//     });
//   }
// });



// Admin Dashboard
app.get(
  "/admin/dashboard",
  authenticateUser,
  authorizeRoles("Admin"),
  async (req, res) => {
    try {
      // Get all users
      const result = await db.query(
        `SELECT id, name, email, role
         FROM users
         ORDER BY id ASC`
      );

      res.status(200).json({
        message: "Welcome to Admin Dashboard",

        admin: req.user,

        totalUsers: result.rows.length,

        users: result.rows,
      });
    } catch (error) {
      console.error("Admin dashboard error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);


//see admin get all users 
app.get(
  "/admin/users",
  authenticateUser,
  authorizeRoles("Admin"),
  async (req, res) => {
    try {
      const result = await db.query(
        `SELECT id, name, email, role
         FROM users
         ORDER BY id ASC`
      );

      res.status(200).json({
        totalUsers: result.rows.length,
        users: result.rows,
      });
    } catch (error) {
      console.error("Get users error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);


// ==========================================
// ADMIN - GET SINGLE USER DETAILS
// ==========================================

app.get(
  "/admin/users/:id",
  authenticateUser,
  authorizeRoles("Admin"),
  async (req, res) => {
    const userId = Number(req.params.id);

    // console.log("Requested User ID:", userId);

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({
        error: "Invalid user ID",
      });
    }

    try {
      const result = await db.query(
        `SELECT id, name, email, role
         FROM users
         WHERE id = $1`,
        [userId]
      );

      console.log("Database result:", result.rows);

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "User not found",
        });
      }

      return res.status(200).json({
        message: "User details retrieved successfully",
        user: result.rows[0],
      });
    } catch (error) {
      console.error("Get single user error:", error);

      return res.status(500).json({
        error: "Server Error",
      });
    }
  }
);



// admin can update users role 
app.patch(
  "/users/role/:id",
  authenticateUser,
  authorizeRoles("Admin"),
  async (req, res) => {
    const { id } = req.params;
    const { role } = req.body;

    // Admin can only assign these roles
    const allowedRoles = ["User", "Shopkeeper"];

    if (!allowedRoles.includes(role)) {
      return res.status(400).json({
        error: "Invalid role. Admin can assign User or Shopkeeper only",
      });
    }

    try {
      const result = await db.query(
        `UPDATE users
         SET role = $1
         WHERE id = $2
         RETURNING id, name, email, role`,
        [role, id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "User not found",
        });
      }

      res.status(200).json({
        message: "User role updated successfully",
        user: result.rows[0],
      });
    } catch (error) {
      console.error("Role update error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);



// ==========================================
// ADMIN - DELETE USER
// ==========================================

app.delete(
  "/admin/users/:id",
  authenticateUser,
  authorizeRoles("Admin"),
  async (req, res) => {
    const { id } = req.params;

    try {
      // Find the user first
      const existingUser = await db.query(
        `SELECT id, name, email, role
         FROM users
         WHERE id = $1`,
        [id]
      );

      // User doesn't exist
      if (existingUser.rows.length === 0) {
        return res.status(404).json({
          error: "User not found",
        });
      }

      const user = existingUser.rows[0];

      // ==========================================
      // PREVENT ADMIN DELETION
      // ==========================================

      if (user.role === "Admin") {
        return res.status(403).json({
          error: "Admin users cannot be deleted",
        });
      }

      // ==========================================
      // DELETE USER / SHOPKEEPER
      // ==========================================

      const result = await db.query(
        `DELETE FROM users
         WHERE id = $1
         RETURNING id, name, email, role`,
        [id]
      );

      res.status(200).json({
        message: "User deleted successfully",
        deletedUser: result.rows[0],
      });
    } catch (error) {
      console.error("Delete user error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);


// ShopKeeper Role
// ==========================================
// SHOPKEEPER - CREATE PRODUCT
// ==========================================


// ==========================================
// SHOPKEEPER - DASHBOARD
// ==========================================

app.get(
  "/shopkeeper-dashboard",
  authenticateUser,
  authorizeRoles("Shopkeeper"),
  async (req, res) => {
    try {
      res.status(200).json({
        message: "Welcome to your Shopkeeper Dashboard",
        user: {
          id: req.user.id,
          email: req.user.email,
          role: req.user.role,
        },
      });
    } catch (error) {
      console.error("Shopkeeper dashboard error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);



app.post(
  "/shopkeeper/products",
  authenticateUser,
  authorizeRoles("Shopkeeper"),
  async (req, res) => {
    const {
      name,
      description,
      price,
      stock,
      category,
      image_url,
    } = req.body;

    // Validation
    if (!name || price === undefined || stock === undefined) {
      return res.status(400).json({
        error: "Name, price and stock are required",
      });
    }

    if (Number(price) < 0) {
      return res.status(400).json({
        error: "Price cannot be negative",
      });
    }

    if (Number(stock) < 0) {
      return res.status(400).json({
        error: "Stock cannot be negative",
      });
    }

    try {
      // Logged-in shopkeeper ID
      const shopkeeperId = req.user.id;

      const result = await db.query(
        `INSERT INTO products
        (
          name,
          description,
          price,
          stock,
          category,
          image_url,
          shopkeeper_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *`,
        [
          name,
          description || null,
          Number(price),
          Number(stock),
          category || null,
          image_url || null,
          shopkeeperId,
        ]
      );

      res.status(201).json({
        message: "Product created successfully",
        product: result.rows[0],
      });
    } catch (error) {
      console.error("Create product error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);


// ==========================================
// SHOPKEEPER - GET ALL OWN PRODUCTS
// ==========================================

app.get(
  "/products",
  async (req, res) => {
    try {
      // Pagination
      const page = Math.max(Number(req.query.page) || 1, 1);
      const limit = 10;
      const offset = (page - 1) * limit;

      // Search
      const search = (req.query.search || "").trim();
      const searchValue = `%${search}%`;

      // Get total products
      const countResult = await db.query(
        `SELECT COUNT(*)
         FROM products
         WHERE
           name ILIKE $1
           OR description ILIKE $1
           OR category ILIKE $1`,
        [searchValue]
      );

      const totalProducts = Number(countResult.rows[0].count);

      // Get products
      const result = await db.query(
        `SELECT
          id,
          name,
          description,
          price,
          stock,
          category,
          image_url,
          shopkeeper_id,
          created_at,
          updated_at
        FROM products
        WHERE
          name ILIKE $1
          OR description ILIKE $1
          OR category ILIKE $1
        ORDER BY id DESC
        LIMIT $2
        OFFSET $3`,
        [searchValue, limit, offset]
      );

      // Total pages
      const totalPages = Math.ceil(totalProducts / limit);

      res.status(200).json({
        totalProducts,
        currentPage: page,
        productsPerPage: limit,
        totalPages,
        hasNextPage: page < totalPages,
        hasPreviousPage: page > 1,
        search,
        products: result.rows,
      });
    } catch (error) {
      console.error("Get all products error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);



// ==========================================
// SHOPKEEPER - GET SINGLE PRODUCT
// ==========================================

app.get(
  "/products/:id",
  async (req, res) => {
    const productId = Number(req.params.id);

    // Validate product ID
    if (!Number.isInteger(productId) || productId <= 0) {
      return res.status(400).json({
        error: "Invalid product ID",
      });
    }

    try {
      const result = await db.query(
        `SELECT
          id,
          name,
          description,
          price,
          stock,
          category,
          image_url,
          shopkeeper_id,
          created_at,
          updated_at
        FROM products
        WHERE id = $1`,
        [productId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Product not found",
        });
      }

      res.status(200).json({
        message: "Product retrieved successfully",
        product: result.rows[0],
      });
    } catch (error) {
      console.error("Get single product error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);



// ==========================================
// SHOPKEEPER - UPDATE PRODUCT
// ==========================================

app.patch(
  "/shopkeeper/products/:id",
  authenticateUser,
  authorizeRoles("Shopkeeper"),
  async (req, res) => {
    const productId = Number(req.params.id);

    const {
      name,
      description,
      price,
      stock,
      category,
      image_url,
    } = req.body;

    if (!Number.isInteger(productId) || productId <= 0) {
      return res.status(400).json({
        error: "Invalid product ID",
      });
    }

    try {
      const shopkeeperId = req.user.id;

      // Check product ownership
      const existingProduct = await db.query(
        `SELECT id
         FROM products
         WHERE id = $1
         AND shopkeeper_id = $2`,
        [productId, shopkeeperId]
      );

      if (existingProduct.rows.length === 0) {
        return res.status(404).json({
          error: "Product not found",
        });
      }

      const result = await db.query(
        `UPDATE products
         SET
           name = COALESCE($1, name),
           description = COALESCE($2, description),
           price = COALESCE($3, price),
           stock = COALESCE($4, stock),
           category = COALESCE($5, category),
           image_url = COALESCE($6, image_url),
           updated_at = CURRENT_TIMESTAMP
         WHERE id = $7
         AND shopkeeper_id = $8
         RETURNING *`,
        [
          name ?? null,
          description ?? null,
          price !== undefined ? Number(price) : null,
          stock !== undefined ? Number(stock) : null,
          category ?? null,
          image_url ?? null,
          productId,
          shopkeeperId,
        ]
      );

      res.status(200).json({
        message: "Product updated successfully",
        product: result.rows[0],
      });
    } catch (error) {
      console.error("Update product error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);





// ==========================================
// SHOPKEEPER - DELETE PRODUCT
// ==========================================

app.delete(
  "/shopkeeper/products/:id",
  authenticateUser,
  authorizeRoles("Shopkeeper"),
  async (req, res) => {
    const productId = Number(req.params.id);

    if (!Number.isInteger(productId) || productId <= 0) {
      return res.status(400).json({
        error: "Invalid product ID",
      });
    }

    try {
      const shopkeeperId = req.user.id;

      const result = await db.query(
        `DELETE FROM products
         WHERE id = $1
         AND shopkeeper_id = $2
         RETURNING id, name, price, stock, category`,
        [productId, shopkeeperId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Product not found",
        });
      }

      res.status(200).json({
        message: "Product deleted successfully",
        deletedProduct: result.rows[0],
      });
    } catch (error) {
      console.error("Delete product error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);





// 
// Method	Endpoint	Purpose	Login
// POST	/cart	Add product	✅
// GET	/cart	Show user's cart	✅
// PATCH	/cart/:cartItemId	Update quantity	✅
// DELETE	/cart/:cartItemId	Remove item	✅
// DELETE	/cart	Clear cart	✅



// Add to Cart Products api
app.post(
  "/cart",
  authenticateUser,
  async (req, res) => {
    const { productId, quantity } = req.body;

    // Validate product ID
    const parsedProductId = Number(productId);

    if (!Number.isInteger(parsedProductId) || parsedProductId <= 0) {
      return res.status(400).json({
        error: "Invalid product ID",
      });
    }

    // Validate quantity
    const parsedQuantity = Number(quantity) || 1;

    if (!Number.isInteger(parsedQuantity) || parsedQuantity <= 0) {
      return res.status(400).json({
        error: "Quantity must be a positive integer",
      });
    }

    try {
      const userId = req.user.id;

      // Check product
      const productResult = await db.query(
        `SELECT
          id,
          name,
          price,
          stock,
          image_url
        FROM products
        WHERE id = $1`,
        [parsedProductId]
      );

      if (productResult.rows.length === 0) {
        return res.status(404).json({
          error: "Product not found",
        });
      }

      const product = productResult.rows[0];

      // Check stock
      if (product.stock <= 0) {
        return res.status(400).json({
          error: "Product is out of stock",
        });
      }

      if (parsedQuantity > product.stock) {
        return res.status(400).json({
          error: `Only ${product.stock} items available in stock`,
        });
      }

      // Find user's cart
      let cartResult = await db.query(
        `SELECT id
         FROM carts
         WHERE user_id = $1`,
        [userId]
      );

      let cartId;

      // Create cart if it doesn't exist
      if (cartResult.rows.length === 0) {
        const newCart = await db.query(
          `INSERT INTO carts (user_id)
           VALUES ($1)
           RETURNING id`,
          [userId]
        );

        cartId = newCart.rows[0].id;
      } else {
        cartId = cartResult.rows[0].id;
      }

      // Check if product already exists in cart
      const existingItem = await db.query(
        `SELECT id, quantity
         FROM cart_items
         WHERE cart_id = $1
         AND product_id = $2`,
        [cartId, parsedProductId]
      );

      if (existingItem.rows.length > 0) {
        const currentQuantity = existingItem.rows[0].quantity;
        const newQuantity = currentQuantity + parsedQuantity;

        // Check stock again
        if (newQuantity > product.stock) {
          return res.status(400).json({
            error: `Only ${product.stock} items available in stock`,
          });
        }

        const updatedItem = await db.query(
          `UPDATE cart_items
           SET
             quantity = $1,
             updated_at = CURRENT_TIMESTAMP
           WHERE id = $2
           RETURNING *`,
          [newQuantity, existingItem.rows[0].id]
        );

        return res.status(200).json({
          message: "Product quantity updated in cart",
          cartItem: updatedItem.rows[0],
        });
      }

      // Add new product to cart
      const result = await db.query(
        `INSERT INTO cart_items
          (cart_id, product_id, quantity)
         VALUES ($1, $2, $3)
         RETURNING *`,
        [cartId, parsedProductId, parsedQuantity]
      );

      res.status(201).json({
        message: "Product added to cart successfully",
        cartItem: result.rows[0],
      });
    } catch (error) {
      console.error("Add to cart error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);


// show all product cart
app.get(
  "/cart",
  authenticateUser,
  async (req, res) => {
    try {
      const userId = req.user.id;

      const result = await db.query(
        `SELECT
          c.id AS cart_id,

          ci.id AS cart_item_id,
          ci.quantity,

          p.id AS product_id,
          p.name,
          p.description,
          p.price,
          p.stock,
          p.category,
          p.image_url,

          (p.price * ci.quantity) AS subtotal,

          ci.created_at,
          ci.updated_at

        FROM carts c

        LEFT JOIN cart_items ci
          ON c.id = ci.cart_id

        LEFT JOIN products p
          ON ci.product_id = p.id

        WHERE c.user_id = $1

        ORDER BY ci.id DESC`,
        [userId]
      );

      // User doesn't have a cart
      if (result.rows.length === 0) {
        return res.status(200).json({
          message: "Your cart is empty",
          totalItems: 0,
          totalAmount: 0,
          cart: [],
        });
      }

      // Calculate total items
      const totalItems = result.rows.reduce(
        (total, item) => total + Number(item.quantity || 0),
        0
      );

      // Calculate total amount
      const totalAmount = result.rows.reduce(
        (total, item) =>
          total + Number(item.subtotal || 0),
        0
      );

      res.status(200).json({
        message: "Cart retrieved successfully",

        cartId: result.rows[0].cart_id,

        totalItems,

        totalAmount: totalAmount.toFixed(2),

        cart: result.rows,
      });
    } catch (error) {
      console.error("Get cart error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);



// update cart item + /-
app.patch(
  "/cart/:cartItemId",
  authenticateUser,
  async (req, res) => {
    const cartItemId = Number(req.params.cartItemId);
    const { quantity } = req.body;

    if (!Number.isInteger(cartItemId) || cartItemId <= 0) {
      return res.status(400).json({
        error: "Invalid cart item ID",
      });
    }

    const parsedQuantity = Number(quantity);

    if (!Number.isInteger(parsedQuantity) || parsedQuantity <= 0) {
      return res.status(400).json({
        error: "Quantity must be a positive integer",
      });
    }

    try {
      const userId = req.user.id;

      // Check cart item belongs to logged-in user
      const itemResult = await db.query(
        `SELECT
          ci.id,
          ci.product_id,
          p.stock
         FROM cart_items ci

         JOIN carts c
           ON ci.cart_id = c.id

         JOIN products p
           ON ci.product_id = p.id

         WHERE ci.id = $1
         AND c.user_id = $2`,
        [cartItemId, userId]
      );

      if (itemResult.rows.length === 0) {
        return res.status(404).json({
          error: "Cart item not found",
        });
      }

      const item = itemResult.rows[0];

      // Check stock
      if (parsedQuantity > item.stock) {
        return res.status(400).json({
          error: `Only ${item.stock} items available in stock`,
        });
      }

      const result = await db.query(
        `UPDATE cart_items
         SET
           quantity = $1,
           updated_at = CURRENT_TIMESTAMP
         WHERE id = $2
         RETURNING *`,
        [parsedQuantity, cartItemId]
      );

      res.status(200).json({
        message: "Cart quantity updated successfully",
        cartItem: result.rows[0],
      });
    } catch (error) {
      console.error("Update cart error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);



// Remove Product From Cart
app.delete(
  "/cart/:cartItemId",
  authenticateUser,
  async (req, res) => {
    const cartItemId = Number(req.params.cartItemId);

    if (!Number.isInteger(cartItemId) || cartItemId <= 0) {
      return res.status(400).json({
        error: "Invalid cart item ID",
      });
    }

    try {
      const userId = req.user.id;

      const result = await db.query(
        `DELETE FROM cart_items ci
         USING carts c
         WHERE ci.id = $1
         AND ci.cart_id = c.id
         AND c.user_id = $2
         RETURNING
           ci.id,
           ci.product_id,
           ci.quantity`,
        [cartItemId, userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Cart item not found",
        });
      }

      res.status(200).json({
        message: "Product removed from cart successfully",
        removedItem: result.rows[0],
      });
    } catch (error) {
      console.error("Remove cart item error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);




// Clear all Entire Cart

app.delete(
  "/cart",
  authenticateUser,
  async (req, res) => {
    try {
      const userId = req.user.id;

      const result = await db.query(
        `DELETE FROM cart_items
         WHERE cart_id = (
           SELECT id
           FROM carts
           WHERE user_id = $1
         )
         RETURNING id`,
        [userId]
      );

      res.status(200).json({
        message: "Cart cleared successfully",
        deletedItems: result.rows.length,
      });
    } catch (error) {
      console.error("Clear cart error:", error.message);

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);





// | Method   | Endpoint              | Purpose                |
// | -------- | --------------------- | ---------------------- |
// | `GET`    | `/products`           | All products           |
// | `GET`    | `/products/:id`       | Product details        |
// | `POST`   | `/cart`               | Add to cart            |
// | `GET`    | `/cart`               | Show cart              |
// | `PATCH`  | `/cart/:cartItemId`   | Update cart quantity   |
// | `DELETE` | `/cart/:cartItemId`   | Remove cart item       |
// | `DELETE` | `/cart`               | Clear cart             |
// | `POST`   | `/checkout`           | Create order from cart |
// | `PATCH`  | `/orders/:id/confirm` | Confirm order          |
// | `GET`    | `/orders`             | User's order history   |
// | `GET`    | `/orders/:id`         | Single order details   |


// login user checkout api
app.post(
  "/checkout",
  authenticateUser,
  async (req, res) => {
    const {
      shippingName,
      shippingPhone,
      shippingAddress,
    } = req.body;

    if (
      !shippingName ||
      !shippingPhone ||
      !shippingAddress
    ) {
      return res.status(400).json({
        error:
          "Shipping name, phone and address are required",
      });
    }

    const client = await db.connect();

    try {
      const userId = req.user.id;

      await client.query("BEGIN");

      // --------------------------------
      // 1. Find user's cart
      // --------------------------------
      const cartResult = await client.query(
        `SELECT id
         FROM carts
         WHERE user_id = $1`,
        [userId]
      );

      if (cartResult.rows.length === 0) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error: "Your cart is empty",
        });
      }

      const cartId = cartResult.rows[0].id;

      // --------------------------------
      // 2. Get cart items + lock products
      // --------------------------------
      const cartItemsResult = await client.query(
        `SELECT
          ci.id AS cart_item_id,
          ci.product_id,
          ci.quantity,
          p.name,
          p.price,
          p.stock,
          p.image_url

         FROM cart_items ci

         JOIN products p
           ON ci.product_id = p.id

         WHERE ci.cart_id = $1

         FOR UPDATE`,
        [cartId]
      );

      if (cartItemsResult.rows.length === 0) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error: "Your cart is empty",
        });
      }

      const cartItems = cartItemsResult.rows;

      let totalAmount = 0;

      // --------------------------------
      // 3. Check stock
      // --------------------------------
      for (const item of cartItems) {
        if (item.stock <= 0) {
          await client.query("ROLLBACK");

          return res.status(400).json({
            error: `${item.name} is out of stock`,
          });
        }

        if (item.quantity > item.stock) {
          await client.query("ROLLBACK");

          return res.status(400).json({
            error:
              `Only ${item.stock} ${item.name} available in stock`,
          });
        }

        const subtotal =
          Number(item.price) *
          Number(item.quantity);

        totalAmount += subtotal;
      }

      // --------------------------------
      // 4. Create order
      // --------------------------------
      const orderResult = await client.query(
        `INSERT INTO orders
        (
          user_id,
          total_amount,
          status,
          payment_method,
          shipping_name,
          shipping_phone,
          shipping_address
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)

        RETURNING *`,
        [
          userId,
          totalAmount,
          "Pending",
          "COD",
          shippingName,
          shippingPhone,
          shippingAddress,
        ]
      );

      const order = orderResult.rows[0];

      // --------------------------------
      // 5. Create order items
      // --------------------------------
      for (const item of cartItems) {
        const subtotal =
          Number(item.price) *
          Number(item.quantity);

        await client.query(
          `INSERT INTO order_items
          (
            order_id,
            product_id,
            product_name,
            product_price,
            quantity,
            subtotal
          )
          VALUES ($1, $2, $3, $4, $5, $6)`,
          [
            order.id,
            item.product_id,
            item.name,
            item.price,
            item.quantity,
            subtotal,
          ]
        );

        // --------------------------------
        // 6. Deduct stock
        // --------------------------------
        await client.query(
          `UPDATE products
           SET
             stock = stock - $1,
             updated_at = CURRENT_TIMESTAMP
           WHERE id = $2`,
          [
            item.quantity,
            item.product_id,
          ]
        );
      }

      // --------------------------------
      // 7. Clear cart
      // --------------------------------
      await client.query(
        `DELETE FROM cart_items
         WHERE cart_id = $1`,
        [cartId]
      );

      // --------------------------------
      // 8. Commit
      // --------------------------------
      await client.query("COMMIT");

      res.status(201).json({
        message: "Checkout successful",

        order: {
          id: order.id,
          totalAmount: order.total_amount,
          status: order.status,
          paymentMethod: order.payment_method,
          shippingName: order.shipping_name,
          shippingPhone: order.shipping_phone,
          shippingAddress: order.shipping_address,
          createdAt: order.created_at,
        },
      });

    } catch (error) {
      await client.query("ROLLBACK");

      console.error(
        "Checkout error:",
        error.message
      );

      res.status(500).json({
        error: "Checkout failed",
      });

    } finally {
      client.release();
    }
  }
);




// Create order from cart 
// order confirm api 
app.patch(
  "/orders/:id/confirm",
  authenticateUser,
  async (req, res) => {
    const orderId = Number(req.params.id);

    if (
      !Number.isInteger(orderId) ||
      orderId <= 0
    ) {
      return res.status(400).json({
        error: "Invalid order ID",
      });
    }

    try {
      const userId = req.user.id;

      const result = await db.query(
        `UPDATE orders
         SET
           status = 'Confirmed',
           updated_at = CURRENT_TIMESTAMP

         WHERE id = $1
         AND user_id = $2
         AND status = 'Pending'

         RETURNING *`,
        [
          orderId,
          userId,
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error:
            "Order not found or order cannot be confirmed",
        });
      }

      res.status(200).json({
        message:
          "Order confirmed successfully",

        order: result.rows[0],
      });

    } catch (error) {
      console.error(
        "Confirm order error:",
        error.message
      );

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);



// see all orders api
app.get(
  "/orders",
  authenticateUser,
  async (req, res) => {
    try {
      const userId = req.user.id;

      const result = await db.query(
        `SELECT
          id,
          total_amount,
          status,
          payment_method,
          shipping_name,
          shipping_phone,
          shipping_address,
          created_at,
          updated_at
        FROM orders
        WHERE user_id = $1
        ORDER BY id DESC`,
        [userId]
      );

      res.status(200).json({
        totalOrders: result.rows.length,
        orders: result.rows,
      });
    } catch (error) {
      console.error(
        "Get orders error:",
        error.message
      );

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);



app.get(
  "/orders/:id",
  authenticateUser,
  async (req, res) => {
    const orderId = Number(req.params.id);

    if (
      !Number.isInteger(orderId) ||
      orderId <= 0
    ) {
      return res.status(400).json({
        error: "Invalid order ID",
      });
    }

    try {
      const userId = req.user.id;

      const orderResult = await db.query(
        `SELECT
          id,
          total_amount,
          status,
          payment_method,
          shipping_name,
          shipping_phone,
          shipping_address,
          created_at,
          updated_at
        FROM orders
        WHERE id = $1
        AND user_id = $2`,
        [orderId, userId]
      );

      if (orderResult.rows.length === 0) {
        return res.status(404).json({
          error: "Order not found",
        });
      }

      const itemsResult = await db.query(
        `SELECT
          id,
          product_id,
          product_name,
          product_price,
          quantity,
          subtotal,
          created_at
        FROM order_items
        WHERE order_id = $1
        ORDER BY id ASC`,
        [orderId]
      );

      res.status(200).json({
        message: "Order retrieved successfully",

        order: orderResult.rows[0],

        items: itemsResult.rows,
      });
    } catch (error) {
      console.error(
        "Get single order error:",
        error.message
      );

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);


  

// Shopkeeper Order Dashboard Oparation 
// | Method | Endpoint                        | Purpose                |
// | ------ | ------------------------------- | ---------------------- |
// | GET    | `/shopkeeper/dashboard`         | Dashboard statistics   |
// | GET    | `/shopkeeper/orders`            | All relevant orders    |
// | GET    | `/shopkeeper/orders/:id`        | Order details          |
// | PATCH  | `/shopkeeper/orders/:id/status` | Change status          |
// | PATCH  | `/shopkeeper/orders/:id/cancel` | Cancel + restore stock |




app.get(
  "/shopkeeper/dashboard",
  authenticateUser,
  authorizeRoles("Shopkeeper"),
  async (req, res) => {
    try {
      const shopkeeperId = req.user.id;

      // Total products
      const productsResult = await db.query(
        `SELECT COUNT(*) AS total_products
         FROM products
         WHERE shopkeeper_id = $1`,
        [shopkeeperId]
      );

      // Total orders containing shopkeeper products
      const ordersResult = await db.query(
        `SELECT COUNT(DISTINCT oi.order_id) AS total_orders
         FROM order_items oi
         JOIN products p
           ON oi.product_id = p.id
         WHERE p.shopkeeper_id = $1`,
        [shopkeeperId]
      );

      // Pending orders
      const pendingResult = await db.query(
        `SELECT COUNT(DISTINCT oi.order_id) AS pending_orders
         FROM order_items oi
         JOIN products p
           ON oi.product_id = p.id
         JOIN orders o
           ON oi.order_id = o.id
         WHERE p.shopkeeper_id = $1
         AND o.status = 'Pending'`,
        [shopkeeperId]
      );

      // Confirmed orders
      const confirmedResult = await db.query(
        `SELECT COUNT(DISTINCT oi.order_id) AS confirmed_orders
         FROM order_items oi
         JOIN products p
           ON oi.product_id = p.id
         JOIN orders o
           ON oi.order_id = o.id
         WHERE p.shopkeeper_id = $1
         AND o.status = 'Confirmed'`,
        [shopkeeperId]
      );

      // Delivered orders
      const deliveredResult = await db.query(
        `SELECT COUNT(DISTINCT oi.order_id) AS delivered_orders
         FROM order_items oi
         JOIN products p
           ON oi.product_id = p.id
         JOIN orders o
           ON oi.order_id = o.id
         WHERE p.shopkeeper_id = $1
         AND o.status = 'Delivered'`,
        [shopkeeperId]
      );

      // Shopkeeper's sales amount
      const salesResult = await db.query(
        `SELECT COALESCE(SUM(oi.subtotal), 0) AS total_sales
         FROM order_items oi
         JOIN products p
           ON oi.product_id = p.id
         JOIN orders o
           ON oi.order_id = o.id
         WHERE p.shopkeeper_id = $1
         AND o.status = 'Delivered'`,
        [shopkeeperId]
      );

      res.status(200).json({
        message: "Shopkeeper dashboard retrieved successfully",

        dashboard: {
          totalProducts: Number(
            productsResult.rows[0].total_products
          ),

          totalOrders: Number(
            ordersResult.rows[0].total_orders
          ),

          pendingOrders: Number(
            pendingResult.rows[0].pending_orders
          ),

          confirmedOrders: Number(
            confirmedResult.rows[0].confirmed_orders
          ),

          deliveredOrders: Number(
            deliveredResult.rows[0].delivered_orders
          ),

          totalSales: Number(
            salesResult.rows[0].total_sales
          ).toFixed(2),
        },
      });
    } catch (error) {
      console.error(
        "Shopkeeper dashboard error:",
        error.message
      );

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);


// shopkeeper can see single orders
app.get(
  "/shopkeeper/orders/:id",
  authenticateUser,
  authorizeRoles("Shopkeeper"),
  async (req, res) => {
    const orderId = Number(req.params.id);

    if (
      !Number.isInteger(orderId) ||
      orderId <= 0
    ) {
      return res.status(400).json({
        error: "Invalid order ID",
      });
    }

    try {
      const shopkeeperId = req.user.id;

      // Get order
      const orderResult = await db.query(
        `SELECT DISTINCT
          o.id,
          o.user_id,
          u.name AS customer_name,
          u.email AS customer_email,
          o.total_amount,
          o.status,
          o.payment_method,
          o.shipping_name,
          o.shipping_phone,
          o.shipping_address,
          o.created_at,
          o.updated_at
         FROM orders o

         JOIN users u
           ON o.user_id = u.id

         JOIN order_items oi
           ON o.id = oi.order_id

         JOIN products p
           ON oi.product_id = p.id

         WHERE o.id = $1
         AND p.shopkeeper_id = $2`,
        [
          orderId,
          shopkeeperId,
        ]
      );

      if (orderResult.rows.length === 0) {
        return res.status(404).json({
          error:
            "Order not found or you do not have access to this order",
        });
      }

      // Get only this shopkeeper's products
      const itemsResult = await db.query(
        `SELECT
          oi.id,
          oi.product_id,
          oi.product_name,
          oi.product_price,
          oi.quantity,
          oi.subtotal,
          oi.created_at
         FROM order_items oi

         JOIN products p
           ON oi.product_id = p.id

         WHERE oi.order_id = $1
         AND p.shopkeeper_id = $2

         ORDER BY oi.id ASC`,
        [
          orderId,
          shopkeeperId,
        ]
      );

      res.status(200).json({
        message: "Order retrieved successfully",

        order: orderResult.rows[0],

        items: itemsResult.rows,
      });
    } catch (error) {
      console.error(
        "Shopkeeper single order error:",
        error.message
      );

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);




// shopkeeper update order status 
app.patch(
  "/shopkeeper/orders/:id/status",
  authenticateUser,
  authorizeRoles("Shopkeeper"),
  async (req, res) => {
    const orderId = Number(req.params.id);

    const { status } = req.body;

    if (
      !Number.isInteger(orderId) ||
      orderId <= 0
    ) {
      return res.status(400).json({
        error: "Invalid order ID",
      });
    }

    const statusFlow = {
      Pending: [
        "Confirmed",
        "Cancelled",
      ],

      Confirmed: [
        "Processing",
        "Cancelled",
      ],

      Processing: [
        "Shipped",
      ],

      Shipped: [
        "Delivered",
      ],

      Delivered: [],

      Cancelled: [],
    };

    try {
      const shopkeeperId = req.user.id;

      // Find order
      const orderResult = await db.query(
        `SELECT DISTINCT
          o.id,
          o.status

         FROM orders o

         JOIN order_items oi
           ON o.id = oi.order_id

         JOIN products p
           ON oi.product_id = p.id

         WHERE o.id = $1
         AND p.shopkeeper_id = $2`,
        [
          orderId,
          shopkeeperId,
        ]
      );

      if (orderResult.rows.length === 0) {
        return res.status(404).json({
          error:
            "Order not found or you do not have access to this order",
        });
      }

      const currentStatus =
        orderResult.rows[0].status;

      const allowedStatuses =
        statusFlow[currentStatus] || [];

      // Check status value
      if (!statusFlow.hasOwnProperty(status)) {
        return res.status(400).json({
          error:
            "Invalid order status",
        });
      }

      // Check transition
      if (
        !allowedStatuses.includes(status)
      ) {
        return res.status(400).json({
          error:
            `Order cannot change from ${currentStatus} to ${status}`,
        });
      }

      // If cancelling, use dedicated cancellation API
      if (status === "Cancelled") {
        return res.status(400).json({
          error:
            "Use /shopkeeper/orders/:id/cancel to cancel an order",
        });
      }

      // Update status
      const result = await db.query(
        `UPDATE orders
         SET
           status = $1,
           updated_at = CURRENT_TIMESTAMP

         WHERE id = $2

         RETURNING *`,
        [
          status,
          orderId,
        ]
      );

      res.status(200).json({
        message:
          "Order status updated successfully",

        order:
          result.rows[0],
      });

    } catch (error) {
      console.error(
        "Shopkeeper status update error:",
        error.message
      );

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);



// Shopkeeper Cancel Order
app.patch(
  "/shopkeeper/orders/:id/cancel",
  authenticateUser,
  authorizeRoles("Shopkeeper"),
  async (req, res) => {
    const orderId = Number(req.params.id);

    if (
      !Number.isInteger(orderId) ||
      orderId <= 0
    ) {
      return res.status(400).json({
        error: "Invalid order ID",
      });
    }

    const client = await db.connect();

    try {
      const shopkeeperId = req.user.id;

      await client.query("BEGIN");

      // --------------------------------
      // 1. Check order belongs to shopkeeper
      // --------------------------------
      const orderResult = await client.query(
        `SELECT DISTINCT
          o.id,
          o.status

         FROM orders o

         JOIN order_items oi
           ON o.id = oi.order_id

         JOIN products p
           ON oi.product_id = p.id

         WHERE o.id = $1
         AND p.shopkeeper_id = $2

         FOR UPDATE`,
        [
          orderId,
          shopkeeperId,
        ]
      );

      if (orderResult.rows.length === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error:
            "Order not found or you do not have access to this order",
        });
      }

      const order =
        orderResult.rows[0];

      // --------------------------------
      // 2. Check current status
      // --------------------------------
      if (
        order.status === "Delivered"
      ) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error:
            "Delivered order cannot be cancelled",
        });
      }

      if (
        order.status === "Cancelled"
      ) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error:
            "Order is already cancelled",
        });
      }

      // --------------------------------
      // 3. Get shopkeeper's order items
      // --------------------------------
      const itemsResult = await client.query(
        `SELECT
          oi.product_id,
          oi.quantity,
          p.stock,
          p.name

         FROM order_items oi

         JOIN products p
           ON oi.product_id = p.id

         WHERE oi.order_id = $1
         AND p.shopkeeper_id = $2

         FOR UPDATE`,
        [
          orderId,
          shopkeeperId,
        ]
      );

      // --------------------------------
      // 4. Restore stock
      // --------------------------------
      for (
        const item of itemsResult.rows
      ) {
        await client.query(
          `UPDATE products
           SET
             stock = stock + $1,
             updated_at = CURRENT_TIMESTAMP
           WHERE id = $2`,
          [
            item.quantity,
            item.product_id,
          ]
        );
      }

      // --------------------------------
      // 5. Cancel order
      // --------------------------------
      const updateResult =
        await client.query(
          `UPDATE orders
           SET
             status = 'Cancelled',
             updated_at = CURRENT_TIMESTAMP

           WHERE id = $1

           RETURNING *`,
          [orderId]
        );

      // --------------------------------
      // 6. Commit transaction
      // --------------------------------
      await client.query("COMMIT");

      res.status(200).json({
        message:
          "Order cancelled and stock restored successfully",

        order:
          updateResult.rows[0],

        restoredItems:
          itemsResult.rows,
      });

    } catch (error) {
      await client.query("ROLLBACK");

      console.error(
        "Shopkeeper cancel order error:",
        error.message
      );

      res.status(500).json({
        error:
          "Failed to cancel order",
      });

    } finally {
      client.release();
    }
  }
);








// see all orders for shopkeeper
app.get(
  "/shopkeeper/orders",
  authenticateUser,
  authorizeRoles("Shopkeeper"),
  async (req, res) => {
    try {
      const shopkeeperId = req.user.id;

      const page = Math.max(
        Number(req.query.page) || 1,
        1
      );

      const limit = 10;

      const offset = (page - 1) * limit;

      const search = (req.query.search || "").trim();

      const status = (req.query.status || "").trim();

      const searchValue = `%${search}%`;

      // Count orders
      const countResult = await db.query(
        `SELECT COUNT(DISTINCT o.id) AS total_orders
         FROM orders o
         JOIN order_items oi
           ON o.id = oi.order_id
         JOIN products p
           ON oi.product_id = p.id
         JOIN users u
           ON o.user_id = u.id
         WHERE p.shopkeeper_id = $1
         AND (
           o.id::TEXT ILIKE $2
           OR u.name ILIKE $2
           OR u.email ILIKE $2
         )
         AND (
           $3 = ''
           OR o.status = $3
         )`,
        [
          shopkeeperId,
          searchValue,
          status,
        ]
      );

      const totalOrders = Number(
        countResult.rows[0].total_orders
      );

      // Get orders
      const result = await db.query(
        `SELECT
          o.id,
          o.user_id,
          u.name AS customer_name,
          u.email AS customer_email,
          o.total_amount,
          o.status,
          o.payment_method,
          o.shipping_name,
          o.shipping_phone,
          o.shipping_address,
          o.created_at,
          o.updated_at
         FROM orders o

         JOIN users u
           ON o.user_id = u.id

         JOIN order_items oi
           ON o.id = oi.order_id

         JOIN products p
           ON oi.product_id = p.id

         WHERE p.shopkeeper_id = $1

         AND (
           o.id::TEXT ILIKE $2
           OR u.name ILIKE $2
           OR u.email ILIKE $2
         )

         AND (
           $3 = ''
           OR o.status = $3
         )

         GROUP BY
           o.id,
           u.name,
           u.email

         ORDER BY o.id DESC

         LIMIT $4
         OFFSET $5`,
        [
          shopkeeperId,
          searchValue,
          status,
          limit,
          offset,
        ]
      );

      const totalPages = Math.ceil(
        totalOrders / limit
      );

      res.status(200).json({
        message: "Shopkeeper orders retrieved successfully",

        totalOrders,

        currentPage: page,

        ordersPerPage: limit,

        totalPages,

        hasNextPage: page < totalPages,

        hasPreviousPage: page > 1,

        search,

        status,

        orders: result.rows,
      });
    } catch (error) {
      console.error(
        "Shopkeeper orders error:",
        error.message
      );

      res.status(500).json({
        error: "Server Error",
      });
    }
  }
);











app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Server Running  on port ${port}`);
});