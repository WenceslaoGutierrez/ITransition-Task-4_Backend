const jwt = require('jsonwebtoken');
const { pool } = require('../db');

async function getUserForAuth(userId, connection) {
  const query = 'SELECT id, email, status FROM users WHERE id = ?';
  const [rows] = await connection.execute(query, [userId]);
  return rows.length > 0 ? rows[0] : null;
}

const protect = async (req, res, next) => {
  let token;
  let connection;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      connection = await pool.getConnection();
      const currentUser = await getUserForAuth(decoded.userId, connection);
      if (!currentUser) return res.status(401).json({ message: 'Not authorized, user associated with token not found' });
      if (currentUser.status === 'blocked') return res.status(403).json({ message: 'Forbidden: Your account is blocked.' });
      req.user = currentUser;
      next();
    } catch (error) {
      if (error.name === 'JsonWebTokenError') return res.status(401).json({ message: 'Not authorized, invalid token (e.g., signature mismatch or malformed)' });
      if (error.name === 'TokenExpiredError') {
        const expiryDate = error.expiredAt ? new Date(error.expiredAt * 1000) : 'N/A';
        return res.status(401).json({ message: `Not authorized, token expired at ${expiryDate}` });
      }
      return res.status(401).json({ message: 'Not authorized, token verification process failed' });
    } finally {
      if (connection) connection.release();
    }
  } else return res.status(401).json({ message: 'Not authorized, no Bearer token provided' });
};

module.exports = { protect };
