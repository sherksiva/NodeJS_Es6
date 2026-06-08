import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { authenticateToken, authorizeRoles } from './middleware/auth.js';

const app = express();
app.use(express.json());

const JWT_SECRET = 'your_super_secret_key';

// Mock in-memory database
const users = [];

// Server started indication
app.get('/', (req, res) => {
  res.send('Welcome to the Node.js ES6 Authentication & Authorization Example!');
});

// 1. AUTHENTICATION: User Registration (Signup)
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password, role } = req.body;

    // Check if user already exists
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password for security
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = {
      id: Date.now(),
      username,
      password: hashedPassword,
      role: role || 'user' // Default role to 'user'
    };

    users.push(newUser);
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user' });
  }
});

// 2. AUTHENTICATION: User Login (Token Issuance)
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user) {
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  // Validate password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  // Sign token containing user identity and roles
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({ token });
});

// 3. AUTHORIZATION: Route accessible to any authenticated user
app.get('/api/dashboard', authenticateToken, (req, res) => {
  res.json({ message: `Welcome to your dashboard, ${req.user.username}!` });
});

// 4. AUTHORIZATION: Route restricted to 'admin' role only
app.get('/api/admin', authenticateToken, authorizeRoles('admin'), (req, res) => {
  res.json({ message: 'Welcome Admin! You have accessed the protected control panel.' });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
