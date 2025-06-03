require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { testConnection } = require('./db');
const app = express();
const PORT = process.env.PORT || 3000;
const corsOptions = { origin: process.env.FRONTEND_URL || 'http://localhost:3000' };
app.use(cors());
app.use(express.json());
const userRoutes = require('./routes/userRoutes');

app.use('/api/users', userRoutes);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} \nhttp://localhost:${PORT}`);
  console.log(`Connected to DB: ${process.env.DB_HOST}`);
});
