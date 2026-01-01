const express = require("express");
const Database = require("better-sqlite3");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const JWT_SECRET = "life_manager_secret";

const app = express();
app.use(cors());
app.use(express.json());

// ================= DB INITIALIZATION =================
const dbPath = path.join(__dirname, "user.db");
const db = new Database(dbPath);

// ================= START SERVER =================
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});

// ================= JWT MIDDLEWARE =================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).send({ message: "Token required" });
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch {
    return res.status(403).send({ message: "Invalid token" });
  }
};

// ================= TEST ROUTE =================
app.get("/", (req, res) => {
  res.send("Backend running successfully 🚀");
});

// ================= AUTH =================

// SIGNUP
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  const existingUser = db
    .prepare("SELECT * FROM users WHERE email = ?")
    .get(email);

  if (existingUser) {
    return res.status(400).send({ message: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  db.prepare(
    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)"
  ).run(name, email, hashedPassword);

  res.send({ message: "User registered successfully" });
});

// LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

  if (!user) {
    return res.status(400).send({ message: "Invalid email or password" });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password_hash);

  if (!isPasswordValid) {
    return res.status(400).send({ message: "Invalid email or password" });
  }

  const token = jwt.sign({ user_id: user.user_id }, JWT_SECRET, {
    expiresIn: "1h",
  });

  res.send({ message: "Login successful", token });
});

// ================= INCOME =================
app.post("/income", authenticateToken, (req, res) => {
  const { monthly_income } = req.body;
  const userId = req.user.user_id;

  if (!monthly_income || monthly_income <= 0) {
    return res.status(400).send({ message: "Invalid income" });
  }

  const existing = db
    .prepare("SELECT * FROM income WHERE user_id = ?")
    .get(userId);

  if (existing) {
    db.prepare("UPDATE income SET monthly_income = ? WHERE user_id = ?").run(
      monthly_income,
      userId
    );
  } else {
    db.prepare(
      "INSERT INTO income (user_id, monthly_income) VALUES (?, ?)"
    ).run(userId, monthly_income);
  }

  res.send({ message: "Income saved successfully" });
});

// ================= GOALS CRUD =================

// CREATE GOAL
app.post("/goals", authenticateToken, (req, res) => {
  const { title, category, target_amount, target_date } = req.body;
  const userId = req.user.user_id;

  db.prepare(
    `INSERT INTO goals
     (user_id, title, category, target_amount, target_date, investment_amount)
     VALUES (?, ?, ?, ?, ?, 0)`
  ).run(userId, title, category, target_amount, target_date);

  res.send({ message: "Goal created successfully" });
});

// GET ALL GOALS
app.get("/goals", authenticateToken, (req, res) => {
  const userId = req.user.user_id;

  const goals = db.prepare("SELECT * FROM goals WHERE user_id = ?").all(userId);

  res.send(goals);
});

// UPDATE GOAL
app.put("/goals/:goalId", authenticateToken, (req, res) => {
  const { goalId } = req.params;
  const { title, category, target_amount, target_date } = req.body;
  const userId = req.user.user_id;

  const result = db
    .prepare(
      `UPDATE goals
     SET title=?, category=?, target_amount=?, target_date=?, updated_at=CURRENT_TIMESTAMP
     WHERE goal_id=? AND user_id=?`
    )
    .run(title, category, target_amount, target_date, goalId, userId);

  if (result.changes === 0) {
    return res.status(404).send({ message: "Goal not found" });
  }

  res.send({ message: "Goal updated successfully" });
});

// DELETE GOAL
app.delete("/goals/:goalId", authenticateToken, (req, res) => {
  const { goalId } = req.params;
  const userId = req.user.user_id;

  db.prepare("DELETE FROM goals WHERE goal_id=? AND user_id=?").run(
    goalId,
    userId
  );

  res.send({ message: "Goal deleted successfully" });
});

// ================= INVESTMENT =================

app.put("/goals/:goalId/invest/edit", authenticateToken, (req, res) => {
  const { goalId } = req.params;
  const { investment_amount } = req.body;
  const userId = req.user.user_id;

  if (investment_amount < 0) {
    return res.status(400).send({ message: "Invalid amount" });
  }

  db.prepare(
    `UPDATE goals
     SET investment_amount = ?
     WHERE goal_id = ? AND user_id = ?`
  ).run(investment_amount, goalId, userId);

  res.send({ message: "Investment updated successfully" });
});

app.delete("/goals/:goalId/invest", authenticateToken, (req, res) => {
  const { goalId } = req.params;
  const userId = req.user.user_id;

  db.prepare(
    `UPDATE goals
     SET investment_amount = 0
     WHERE goal_id = ? AND user_id = ?`
  ).run(goalId, userId);

  res.send({ message: "Investment deleted successfully" });
});

app.put("/goals/:goalId/invest", authenticateToken, (req, res) => {
  const { goalId } = req.params;
  const { investment_amount } = req.body;
  const userId = req.user.user_id;

  if (!investment_amount || investment_amount <= 0) {
    return res.status(400).send({ message: "Invalid investment amount" });
  }

  db.prepare(
    `UPDATE goals
     SET investment_amount = COALESCE(investment_amount, 0) + ?
     WHERE goal_id = ? AND user_id = ?`
  ).run(investment_amount, goalId, userId);

  res.send({ message: "Investment added successfully" });
});

// ================= TASKS =================
app.post("/tasks", authenticateToken, (req, res) => {
  const { goal_id, task_name } = req.body;

  db.prepare("INSERT INTO tasks (goal_id, task_name) VALUES (?, ?)").run(
    goal_id,
    task_name
  );

  res.send({ message: "Task added successfully" });
});

app.get("/goals/:goalId/tasks", authenticateToken, (req, res) => {
  const { goalId } = req.params;

  const tasks = db.prepare("SELECT * FROM tasks WHERE goal_id = ?").all(goalId);

  res.send(tasks);
});

app.put("/tasks/:taskId", authenticateToken, (req, res) => {
  const { taskId } = req.params;
  const { task_name, status } = req.body;

  db.prepare(
    `UPDATE tasks
     SET task_name=?, status=?, updated_at=CURRENT_TIMESTAMP
     WHERE task_id=?`
  ).run(task_name, status, taskId);

  res.send({ message: "Task updated successfully" });
});

app.delete("/tasks/:taskId", authenticateToken, (req, res) => {
  const { taskId } = req.params;

  db.prepare("DELETE FROM tasks WHERE task_id=?").run(taskId);

  res.send({ message: "Task deleted successfully" });
});

// ================= SUMMARY =================
app.get("/summary", authenticateToken, (req, res) => {
  const userId = req.user.user_id;

  const incomeRow = db
    .prepare("SELECT monthly_income FROM income WHERE user_id = ?")
    .get(userId);

  const goals = db
    .prepare("SELECT title, investment_amount FROM goals WHERE user_id = ?")
    .all(userId);

  const totalInvestment = goals.reduce(
    (sum, g) => sum + (g.investment_amount || 0),
    0
  );

  const income = incomeRow?.monthly_income || 0;

  res.send({
    income,
    totalInvestment,
    savings: income - totalInvestment,
    goals,
  });
});
