const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { pool } = require('../db');
const saltRounds = 10;

function ensureRequiredFieldsPresent(body, requiredFields) {
  for (const field of requiredFields) {
    if (!body[field]) {
      const error = new Error(`Please provide ${field}.`);
      error.statusCode = 400;
      throw error;
    }
  }
}

function validateEmailFormat(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    const error = new Error('Invalid email format.');
    error.statusCode = 400;
    throw error;
  }
}

async function checkEmailAvailability(email, connection) {
  const [existingUsers] = await connection.execute('SELECT email FROM users WHERE email = ?', [email]);
  if (existingUsers.length > 0) {
    const error = new Error('Email already registered.');
    error.statusCode = 409;
    throw error;
  }
}

async function generateHashedPassword(password) {
  return await bcrypt.hash(password, saltRounds);
}

async function insertNewUser(userData, connection) {
  const { first_name, last_name, email, hashedPassword, job_title, company } = userData;
  const [result] = await connection.execute('INSERT INTO users (first_name, last_name, email, password_hash, job_title, company) VALUES (?, ?, ?, ?, ?, ?)', [
    first_name,
    last_name,
    email,
    hashedPassword,
    job_title || null,
    company || null
  ]);
  return result.insertId;
}

async function fetchAllUsersFromDB(connection, clientSortBy, clientSortOrder) {
  const columnsToSelect = 'id, first_name, last_name, email, job_title, company, last_login_date, registration_date, status';
  const allowedSortBy = ['id', 'first_name', 'last_name', 'email', 'last_login_date', 'registration_date', 'status'];
  let effectiveSortBy = 'last_login_date';
  if (clientSortBy && allowedSortBy.includes(clientSortBy)) {
    effectiveSortBy = clientSortBy;
  }
  const effectiveSortOrder = clientSortOrder && clientSortOrder.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';
  let orderByClause = '';
  if (effectiveSortBy === 'last_login_date') {
    if (effectiveSortOrder === 'DESC') orderByClause = `ORDER BY \`last_login_date\` IS NULL ASC, \`last_login_date\` DESC, registration_date DESC`;
    else orderByClause = `ORDER BY \`last_login_date\` IS NULL ASC, \`last_login_date\` ASC, registration_date ASC`;
  } else orderByClause = `ORDER BY \`${effectiveSortBy}\` ${effectiveSortOrder}, registration_date DESC`;
  const query = `SELECT ${columnsToSelect} FROM users ${orderByClause}`;
  const [users] = await connection.execute(query);
  return users;
}

async function deleteUserFromDB(userId, connection) {
  const query = 'DELETE FROM users WHERE id = ?';
  const [result] = await connection.execute(query, [userId]);
  return result.affectedRows;
}

async function deleteMultipleUsersFromDB(idsToDelete, connection) {
  if (!idsToDelete || idsToDelete.length === 0) return 0;
  const query = 'DELETE FROM users WHERE id IN (?)';
  try {
    const [result] = await connection.query(query, [idsToDelete]);
    return result.affectedRows;
  } catch (dbError) {
    throw dbError;
  }
}

async function findUserByEmailInDB(email, connection) {
  const query = 'SELECT id, first_name, last_name, email, password_hash, status FROM users WHERE email = ?';
  const [rows] = await connection.execute(query, [email]);
  if (rows.length === 0) return null;
  return rows[0];
}

async function updateUserLastLoginDate(userId, connection) {
  const query = 'UPDATE users SET last_login_date = CURRENT_TIMESTAMP WHERE id = ?';
  await connection.execute(query, [userId]);
}

async function updateStatusForMultipleUsersInDB(userIds, status, connection) {
  if (!userIds || userIds.length === 0) return 0;
  const query = 'UPDATE users SET status = ? WHERE id IN (?)';
  try {
    const [result] = await connection.query(query, [status, userIds]);
    return result.affectedRows;
  } catch (dbError) {
    throw dbError;
  }
}

exports.loginUser = async (req, res) => {
  let connection;
  try {
    const { email, password } = req.body;
    ensureRequiredFieldsPresent(req.body, ['email', 'password']);
    validateEmailFormat(email);
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const user = await findUserByEmailInDB(email, connection);
    if (!user) {
      await connection.rollback();
      return res.status(401).json({ message: 'Invalid email or password.' });
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordMatch) {
      await connection.rollback();
      return res.status(401).json({ message: 'Invalid email or password.' });
    }
    if (user.status === 'blocked') {
      await connection.rollback();
      return res.status(403).json({ message: 'Account is blocked. Please contact support.' });
    }
    await updateUserLastLoginDate(user.id, connection);
    const payload = {
      userId: user.id,
      email: user.email
    };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '10m' });
    await connection.commit();
    res.status(200).json({
      message: 'Login successful!',
      token: token,
      user: {
        id: user.id,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email
      }
    });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Error in loginUser controller:', error.message, error.stack);
    res.status(500).json({ message: 'An error occurred during login.' });
  } finally {
    if (connection) connection.release();
  }
};

exports.logoutUser = async (req, res) => {
  res.status(200).json({ message: 'Logout successful. DISCARDING PENDING IN FRONT.' });
};

exports.updateMultipleUsersStatus = async (req, res) => {
  let connection;
  try {
    const { userIds, status } = req.body;
    if (!Array.isArray(userIds) || userIds.length === 0) return res.status(400).json({ message: 'Please provide a non-empty array of user IDs.' });
    if (!status || !['active', 'blocked'].includes(status.toLowerCase())) return res.status(400).json({ message: "Invalid status provided. Must be 'active' or 'blocked'." });
    const validUserIds = userIds.map((id) => parseInt(id, 10)).filter((id) => !isNaN(id) && id > 0);
    if (validUserIds.length === 0) return res.status(400).json({ message: 'No valid user IDs provided for status update.' });
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const affectedRows = await updateStatusForMultipleUsersInDB(validUserIds, status.toLowerCase(), connection);
    await connection.commit();
    if (affectedRows === 0 && validUserIds.length > 0) {
      return res.status(404).json({ message: 'No users found matching the provided IDs for status update.' });
    }
    res.status(200).json({
      message: `Successfully updated status to '${status.toLowerCase()}' for ${affectedRows} user(s).`
    });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Error in userController.updateMultipleUsersStatus:', error.message, error.stack);
    res.status(500).json({ message: 'An error occurred while updating user statuses.' });
  } finally {
    if (connection) connection.release();
  }
};

// CREATE
exports.registerUser = async (req, res) => {
  let connection;
  try {
    const { first_name, last_name, email, password, job_title, company } = req.body;
    ensureRequiredFieldsPresent(req.body, ['first_name', 'last_name', 'email', 'password']);
    validateEmailFormat(email);
    connection = await pool.getConnection();
    await connection.beginTransaction();
    await checkEmailAvailability(email, connection);
    const hashedPassword = await generateHashedPassword(password);
    const userId = await insertNewUser({ first_name, last_name, email, hashedPassword, job_title, company }, connection);
    await updateUserLastLoginDate(userId, connection);
    await connection.commit();
    const payload = {
      userId: userId,
      email: email
    };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '10m' });
    res.status(201).json({
      message: 'User registered successfully!',
      token: token,
      userId: userId,
      user: { id: userId, first_name, last_name, email, job_title: job_title || null, company: company || null }
    });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Error in registerUser controller:', error.message, error.stack);
    const statusCode = error.statusCode || 500;
    res.status(statusCode).json({ message: error.message || 'An error occurred during registration.' });
  } finally {
    if (connection) connection.release();
  }
};
// READ
exports.getAllUsers = async (req, res) => {
  let connection;
  try {
    const sortBy = req.query.sortBy || 'last_login_date';
    const sortOrder = req.query.sortOrder || 'DESC';
    connection = await pool.getConnection();
    const users = await fetchAllUsersFromDB(connection, sortBy, sortOrder);
    res.status(200).json({
      message: 'Users retrieved successfully!',
      count: users.length,
      users: users
    });
  } catch (error) {
    console.error('Error in userController.getAllUsers:', error.message, error.stack);
    res.status(500).json({ message: 'An error occurred while retrieving users.' });
  } finally {
    if (connection) connection.release();
  }
};
// DELETE
exports.deleteMultipleUsers = async (req, res) => {
  let connection;
  try {
    const { userIds } = req.body;
    if (!Array.isArray(userIds) || userIds.length === 0) return res.status(400).json({ message: 'Please provide an array of user IDs.' });
    const validUserIds = userIds.map((id) => parseInt(id, 10)).filter((id) => !isNaN(id) && id > 0);
    if (validUserIds.length === 0) return res.status(400).json({ message: 'No valid user IDs provided for deletion.' });
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const affectedRows = await deleteMultipleUsersFromDB(validUserIds, connection);
    if (affectedRows === 0) return res.status(404).json({ message: 'No users found matching the provided IDs for deletion, or no valid IDs were provided.' });
    await connection.commit();
    res.status(200).json({ message: `Successfully deleted ${affectedRows} user(s).` });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Error in userController.deleteMultipleUsers:', error.message, error.stack);
    res.status(500).json({ message: 'An error occurred while deleting users.' });
  } finally {
    if (connection) connection.release();
  }
};
