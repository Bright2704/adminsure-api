const mysql = require('mysql2/promise');

// Create a connection pool
const pool = mysql.createPool({
    host: '210.246.202.185',
    user: 'root',
    password: 'GnZORtiCXLNg',
    database: 'asminsure'
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
