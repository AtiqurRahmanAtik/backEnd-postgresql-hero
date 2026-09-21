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
    secure: false,
    sameSite: "lax",
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




// Addto Cart Products api
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




// Clear Entire Cart

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



// 
// Method	Endpoint	Purpose	Login
// POST	/cart	Add product	✅
// GET	/cart	Show user's cart	✅
// PATCH	/cart/:cartItemId	Update quantity	✅
// DELETE	/cart/:cartItemId	Remove item	✅
// DELETE	/cart	Clear cart	✅



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



app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Server Running  on port ${port}`);
});