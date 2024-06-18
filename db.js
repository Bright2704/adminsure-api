const mysql = require('mysql2/promise');

// Create a connection pool
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'my-secret-pw',
    database: 'mydatabase'
});

// Function to find a user by email
async function findUserByEmail(email) {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    return rows[0];
}

module.exports = {
    pool, // Export the connection pool
    findUserByEmail,  // Export the findUserByEmail function
    // Other database functions can be exported here
};
