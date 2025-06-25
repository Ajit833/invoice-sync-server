const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { LowSync } = require("lowdb");
const { JSONFileSync } = require("lowdb/node");

const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json());

const SECRET = "super-secret-key"; // Change this to your own secret key!

// Setup database with default data
const adapter = new JSONFileSync("db.json");
const defaultData = { users: {} };
const db = new LowSync(adapter, { defaultValue: defaultData });
db.read();

// Authentication middleware
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(token, SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(403).json({ error: "Invalid token" });
  }
}

// Register new user
app.post("/auth/register", async (req, res) => {
  const { username, password } = req.body;
  if (db.data.users[username]) return res.status(400).json({ error: "User exists" });

  const hashed = await bcrypt.hash(password, 10);
  db.data.users[username] = { password: hashed, data: {} };
  db.write();
  res.json({ success: true });
});

// Login user
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;
  const user = db.data.users[username];
  if (!user) return res.status(400).json({ error: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: "Wrong password" });

  const token = jwt.sign({ userId: username }, SECRET, { expiresIn: "1d" });
  res.json({ token });
});

// Get full data sync
app.get("/data/full-sync", authenticate, (req, res) => {
  const data = db.data.users[req.userId].data || {};
  res.json(data);
});

// Save full data sync
app.post("/data/full-sync", authenticate, (req, res) => {
  db.data.users[req.userId].data = req.body;
  db.write();
  res.json({ success: true });
});

app.listen(3000, () => {
  console.log("Server running at http://localhost:3000");
});
