import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import mysql from 'mysql2';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import productsRoute from './routes/productRoutes.js';
import sellerRoute from './routes/sellerRoutes.js';
import adminRoutes from './routes/admin.js';

const app = express();
const PORT = 5000;
const JWT_SECRET = 'your_jwt_secret_key'; // Consider using process.env.JWT_SECRET

// ✅ 1. Database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'elwardi',
  password: '2006',
  database: 'db_vinted',
});

db.connect((err) => {
  if (err) throw err;
  console.log('✅ Connected to the database!');
});

// ✅ 2. Middleware
app.use(cors({
  origin: 'http://localhost:8080',
  credentials: true,
}));
app.use(express.json({ limit: '100mb' }));
app.use(bodyParser.json({ limit: '100mb' }));
app.use(cookieParser());

// ✅ 3. Register
app.post('/register', (req, res) => {
  const { username, email, password } = req.body;

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ message: 'Error hashing password' });

    const query = `
      INSERT INTO users (username, email, password, status, role)
      VALUES (?, ?, ?, 'pending', 'user')
    `;

    db.query(query, [username, email, hashedPassword], (err, result) => {
      if (err) {
        console.error('Error registering user:', err);
        return res.status(500).json({ message: 'Registration failed' });
      }

      res.status(201).json({
        message: 'User registered successfully',
        user: { id: result.insertId, username, email },
      });
    });
  });
});

// ✅ 4. Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });

    if (results.length === 0) {
      return res.status(401).json({ message: 'Email not found' });
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) return res.status(500).json({ message: 'Error comparing password' });

      if (!isMatch) return res.status(401).json({ message: 'Incorrect password' });

      const token = jwt.sign(
        { id: user.id, username: user.username, email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: '30d' }
      );

      res.cookie('auth_token', token, {
        httpOnly: true,
        secure: false,
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      });

      const responseData = {
        message: 'Login successful',
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
        },
      };

      if (user.role === 'admin') {
        responseData.redirectUrl = 'http://localhost:8080/admin';
      }

      res.status(200).json(responseData);
    });
  });
});

// ✅ 5. Export database connection for use in other modules
export { db };

// ✅ 6. Current user
app.get('/current-user', (req, res) => {
  const token = req.cookies.auth_token;

  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    db.query(
      'SELECT id, username, email, role FROM users WHERE id = ?',
      [decoded.id],
      (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });

        if (results.length === 0) {
          return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({ user: results[0] });
      }
    );
  } catch (err) {
    console.error('Token verification error:', err);
    res.status(401).json({ message: 'Invalid token' });
  }
});

// ✅ 7. Logout
app.post('/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.status(200).json({ message: 'Logged out successfully' });
});

// ✅ 8. Routes
app.use('/api/products', productsRoute);
app.use('/api/seller', sellerRoute); // Add the seller route
app.use('/', adminRoutes);

// ✅ 9. Start server
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});