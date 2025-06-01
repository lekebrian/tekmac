import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import path, { dirname } from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import axios from 'axios';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import express from 'express';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import jwt from 'jsonwebtoken';
import cors from 'cors';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'tekmac',
};

let db;
(async () => {
  try {
    db = await mysql.createConnection(dbConfig);
    console.log('Connected to the database');
    await createTables();
  } catch (err) {
    console.error('Database connection failed:', err);
    process.exit(1);
  }
})();

app.post('/register', async (req, res) => {
  const { username, email, password, phoneNumber } = req.body;

  if (!username || !email || !password || !phoneNumber) {
    return res.status(400).json({ success: false, error: 'All fields are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.execute(
      "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
      [username, email, hashedPassword]
    );
    // Optionally, you can save phoneNumber if you add a column for it
    res.json({ success: true, redirect: '/pay.html' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Registration failed: ' + error.message });
  }
});
async function createTables() {
  // Users table
  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      tech_skills JSON,
      is_mentor BOOLEAN DEFAULT FALSE,
      bio TEXT,
      experience_level VARCHAR(50),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `);

  // Messages table
  await db.execute(`
    CREATE TABLE IF NOT EXISTS messages (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      sender_id INT UNSIGNED NOT NULL,
      receiver_id INT UNSIGNED NOT NULL,
      message TEXT NOT NULL,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      is_bot_message BOOLEAN DEFAULT FALSE,
      FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
      FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
    ) ENGINE=InnoDB
  `);

  // Mentor connections table
  await db.execute(`
    CREATE TABLE IF NOT EXISTS mentor_connections (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      user_id INT UNSIGNED NOT NULL,
      mentor_id INT UNSIGNED NOT NULL,
      status VARCHAR(20) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
      FOREIGN KEY (mentor_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
    ) ENGINE=InnoDB
  `);

  // Add this to your createTables() function after other tables
await db.execute(`
  CREATE TABLE IF NOT EXISTS ads (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED,
    image_url VARCHAR(255),
    business_name VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    location VARCHAR(100) NOT NULL,
    schedule ENUM('daily', 'weekly', 'monthly') NOT NULL,
    amount INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  ) ENGINE=InnoDB
`);

  // Insert sample mentors
  await insertSampleMentors();
}



app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password are required' });
  }

  try {
    // Check if user exists
    const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(401).json({ success: false, error: 'User not found' });
    }

    const user = users[0];

    // Compare password
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ success: false, error: 'Incorrect password' });
    }

    // Generate a token (optional, but recommended)
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      process.env.JWT_SECRET || 'your_jwt_secret',
      { expiresIn: '2h' }
    );

    // Respond with user info and token
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      },
      token
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error: ' + error.message });
  }
});

// For file uploads
import multer from 'multer';
const upload = multer({ dest: path.join(__dirname, 'public', 'ads') });

// Post a new ad (with image upload)
app.post('/api/ads', upload.single('image'), async (req, res) => {
  try {
    const { business_name, description, location, schedule, amount, user_id } = req.body;
    const image_url = req.file ? `/ads/${req.file.filename}` : null;
    await db.execute(
      "INSERT INTO ads (user_id, image_url, business_name, description, location, schedule, amount) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [user_id, image_url, business_name, description, location, schedule, amount]
    );
    res.json({ success: true, message: "Ad posted successfully!" });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get all ads for display on index.html
app.get('/api/ads',upload.single('image'), async (req, res) => {
  const [ads] = await db.execute("SELECT * FROM ads ORDER BY created_at DESC LIMIT 10");
  res.json(ads);
});

app.post('/api/nkwa-collect', async (req, res) => {
    const { phone, amount } = req.body;
    // Call your Nkwa API here (replace with actual integration)
    try {
        // Example: await nkwa.collect(phone, amount);
        // Simulate success:
        res.json({ success: true, message: "Payment initiated. Please confirm on your phone." });
    } catch (error) {
        res.json({ success: false, error: "Failed to initiate payment." });
    }
});

async function insertSampleMentors() {
  const mentors = [
    {
      username: "sarah_js",
      email: "sarah@example.com",
      password: await bcrypt.hash("password123", 10),
      tech_skills: JSON.stringify(["JavaScript", "React", "Node.js"]),
      is_mentor: true,
      bio: "Full-stack developer with 5 years experience in JavaScript ecosystem",
      experience_level: "Senior",
    },
    {
      username: "mike_python",
      email: "mike@example.com",
      password: await bcrypt.hash("password123", 10),
      tech_skills: JSON.stringify(["Python", "Django", "Machine Learning"]),
      is_mentor: true,
      bio: "Python developer and ML engineer with expertise in data science",
      experience_level: "Senior",
    },
    {
      username: "alex_mobile",
      email: "alex@example.com",
      password: await bcrypt.hash("password123", 10),
      tech_skills: JSON.stringify(["React Native", "Flutter", "iOS", "Android"]),
      is_mentor: true,
      bio: "Mobile app developer specializing in cross-platform solutions",
      experience_level: "Mid-level",
    },
  ];

  for (const mentor of mentors) {
    try {
      await db.execute(
        "INSERT IGNORE INTO users (username, email, password, tech_skills, is_mentor, bio, experience_level) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
          mentor.username,
          mentor.email,
          mentor.password,
          mentor.tech_skills,
          mentor.is_mentor,
          mentor.bio,
          mentor.experience_level,
        ]
      );
    } catch (error) {
      // Ignore duplicate entries
    }
  }
}

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, process.env.JWT_SECRET || "your-secret-key", (err, user) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ error: "Token expired" });
      }
      return res.status(403).json({ error: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

// Auth endpoints
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, techSkills, experienceLevel } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.execute(
      "INSERT INTO users (username, email, password, tech_skills, experience_level) VALUES (?, ?, ?, ?, ?)",
      [username, email, hashedPassword, JSON.stringify(techSkills), experienceLevel]
    );

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(400).json({ error: "Registration failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);

    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET || "your-secret-key");
    res.json({ token, user: { id: user.id, username: user.username, techSkills: user.tech_skills } });
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

// Mentor listing/filtering
app.get("/api/mentors", authenticateToken, async (req, res) => {
  try {
    const { skills } = req.query;
    let query = "SELECT id, username, bio, tech_skills, experience_level FROM users WHERE is_mentor = TRUE";
    let params = [];

    if (skills) {
      const skillsArray = skills.split(",");
      const skillConditions = skillsArray.map(() => "JSON_CONTAINS(tech_skills, ?)").join(" OR ");
      query += ` AND (${skillConditions})`;
      params = skillsArray.map((skill) => `"${skill.trim()}"`);
    }

    const [rows] = await db.execute(query, params);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch mentors" });
  }
});

// Connect with mentor
app.post("/api/connect-mentor", authenticateToken, async (req, res) => {
  try {
    const { mentorId } = req.body;
    const userId = req.user.userId;

    await db.execute("INSERT INTO mentor_connections (user_id, mentor_id) VALUES (?, ?)", [userId, mentorId]);

    res.json({ message: "Connection request sent" });
  } catch (error) {
    res.status(500).json({ error: "Failed to connect with mentor" });
  }
});

// Get messages between users
app.get("/api/messages/:userId", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const currentUserId = req.user.userId;

    const [rows] = await db.execute(
      `SELECT m.*, u.username as sender_username 
       FROM messages m 
       JOIN users u ON m.sender_id = u.id 
       WHERE (m.sender_id = ? AND m.receiver_id = ?) 
          OR (m.sender_id = ? AND m.receiver_id = ?) 
       ORDER BY m.timestamp ASC`,
      [currentUserId, userId, userId, currentUserId]
    );

    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

// Session validation endpoint
app.get("/api/validate-session", authenticateToken, (req, res) => {
  res.json({ valid: true });
});

// Serve mentor.html
app.get('/mentor.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'mentor.html'));
});

// Socket.io chat logic
io.on("connection", (socket) => {
  socket.on("join-room", (userId) => {
    socket.join(userId);
  });

  socket.on("send-message", async (data) => {
    const { senderId, receiverId, message } = data;
    try {
      await db.execute(
        "INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)",
        [senderId, receiverId, message]
      );
      // Emit to receiver
      io.to(receiverId.toString()).emit("receive-message", {
        senderId,
        message,
        timestamp: new Date(),
      });
    } catch (error) {
      // Handle error if needed
    }
  });
});

// --- (Optional) Payment endpoints from your original index.js ---
const baseURL = 'https://api.pay.mynkwa.com';
const headers = {
  'X-API-KEY': process.env.PAY_API_KEY_AUTH,
  'Content-Type': 'application/json',
};

app.post('/collect-payment', async (req, res) => {
  try {
    const { amount, phoneNumber } = req.body;
    if (!amount || !phoneNumber) {
      return res.status(400).json({
        success: false,
        error: 'Amount and phoneNumber are required',
      });
    }

    // 1. Initiate payment with Nkwa API
    const data = { amount, phoneNumber };
    const response = await axios.post(`${baseURL}/collect`, data, { headers });

    if (response.data && response.data.payment && response.data.payment.id) {
      const paymentId = response.data.payment.id;

      // 2. Poll for payment confirmation (every 3s up to 30s)
      let confirmed = false;
      let paymentStatus = null;
      for (let i = 0; i < 10; i++) {
        await new Promise(r => setTimeout(r, 3000));
        const statusRes = await axios.get(`${baseURL}/payments/${paymentId}`, { headers });
        paymentStatus = statusRes.data?.payment?.status;
        if (paymentStatus === 'confirmed' || paymentStatus === 'success' || paymentStatus === 'completed') {
          confirmed = true;
          break;
        }
      }

      if (confirmed) {
        return res.json({ success: true, paymentConfirmed: true, paymentId });
      } else {
        return res.json({
          success: true,
          paymentConfirmed: false,
          paymentId,
          error: "Payment not confirmed yet. Please try again."
        });
      }
    } else {
      return res.status(500).json({
        success: false,
        error: 'Unexpected response from payment gateway.',
        details: response.data,
      });
    }
  } catch (err) {
    res.status(err.response?.status || 500).json({
      success: false,
      error: err.response?.data?.message || 'Internal server error',
    });
  }
});

app.post('/disburse-payment', async (req, res) => {
  try {
    const { amount, phoneNumber } = req.body;
    if (!amount || !phoneNumber) {
      return res.status(400).json({
        success: false,
        error: 'Amount and phoneNumber are required',
      });
    }
    const data = { amount, phoneNumber };
    const response = await axios.post(`${baseURL}/disburse`, data, { headers });
    if (response.data && response.data.payment) {
      res.json({ success: true, data: response.data.payment });
    } else {
      res.status(500).json({
        success: false,
        error: 'Unexpected response from payment gateway.',
        details: response.data,
      });
    }
  } catch (err) {
    res.status(err.response?.status || 500).json({
      success: false,
      error: err.response?.data?.message || 'Internal server error',
    });
  }
});

app.get('/payment/:id', async (req, res) => {
  try {
    const response = await axios.get(`${baseURL}/payments/${req.params.id}`, { headers });
    res.json({
      success: true,
      data: response.data.payment,
    });
  } catch (err) {
    res.status(err.response?.status || 500).json({
      success: false,
      error: err.response?.data?.message || 'Internal server error',
    });
  }
});

// --- End payment endpoints ---

const port = process.env.PORT || 3006;
server.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});