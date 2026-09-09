const { Pool } = require('pg');
require('dotenv').config();


const pool = new Pool({
    user : process.env.DB_USER,
    host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});


// Test PostgreSQL connection
const testConnection = async () => {
  try {
    const result = await pool.query("SELECT NOW()");

    console.log("✅ PostgreSQL connected successfully!");
    console.log("📊 Database:", process.env.DB_NAME);
    console.log("🕒 Database time:", result.rows[0].now);
  } catch (error) {
    console.error("❌ PostgreSQL connection failed!");
    console.error("Error:", error.message);
  }
};

testConnection();



module.exports = pool;