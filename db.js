const mysql = require('mysql2/promise');

const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_DATABASE || 'task_db',
  port: parseInt(process.env.DB_PORT) || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('Successfully connected to the MariaDB database using environment variables!');
    const [rows] = await connection.execute('SELECT 1 + 1 AS solution');
    console.log('The solution to 1+1 is:', rows[0].solution);
    connection.release();
  } catch (error) {
    console.error('Error connecting to the database:', error.message);
    if (error.config && error.config.database) {
      console.error(
        `Configuration details used: DB_HOST=${error.config.host}, DB_USER=${error.config.user}, DB_DATABASE=${error.config.database}, DB_PORT=${error.config.port}`
      );
    }
    if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.error('Access denied. Check your DB_USER and DB_PASSWORD environment variables.');
    }
    if (error.code === 'ER_BAD_DB_ERROR') {
      console.error(`Database '${dbConfig.database}' (read from DB_DATABASE) does not exist or is not accessible.`);
    }
    throw error;
  }
}

module.exports = {
  pool,
  testConnection
};
