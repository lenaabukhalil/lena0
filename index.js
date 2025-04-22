import express from "express";
import bodyParser from "body-parser";
import db from "./db.js";
import bcrypt from "bcrypt";
import { EventEmitter } from "events";
import path from "path";
import { fileURLToPath } from "url";
import { Server } from "socket.io";
import { createServer } from "http";
import nodemailer from "nodemailer";
import cors from "cors";
import session from "express-session";
import { v4 as uuidv4 } from 'uuid';

// Configure __dirname for ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Increase event emitter limit
EventEmitter.defaultMaxListeners = 20;

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.json());
app.use(cors());

// Session middleware setup - IMPORTANT: this must come BEFORE your routes
app.use(
  session({
    secret: "Lena$3C^Hj8p!sK9Wq", // Strong secret key (change in production)
    resave: false,
    saveUninitialized: true, // Set to true to allow saving empty sessions during registration
    cookie: {
      secure: false, // Set to true if using HTTPS
      maxAge: 24 * 60 * 60 * 1000, // Session expires after 24 hours
    },
  })
);

// Debug middleware to log requests
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// View engine setup
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// ======================
// NOTIFICATION SYSTEM
// ======================

// In-memory store for notifications (replace with DB in production)
const notifications = new Map();

// Notification types
const NOTIFICATION_TYPES = {
  NEW_MESSAGE: "NEW_MESSAGE",
  TASK_ASSIGNED: "TASK_ASSIGNED",
  SYSTEM_ALERT: "SYSTEM_ALERT",
};

// Add notification
function addNotification(userId, type, message, data = {}) {
  if (!notifications.has(userId)) {
    notifications.set(userId, []);
  }

  const notification = {
    id: Date.now(),
    type,
    message,
    data,
    timestamp: new Date(),
    read: false,
  };

  notifications.get(userId).push(notification);
  return notification;
}

// Mark notification as read
function markAsRead(userId, notificationId) {
  if (notifications.has(userId)) {
    const notification = notifications
      .get(userId)
      .find((n) => n.id === notificationId);
    if (notification) {
      notification.read = true;
      return true;
    }
  }
  return false;
}

// Get user notifications
function getUserNotifications(userId, unreadOnly = false) {
  if (!notifications.has(userId)) {
    return [];
  }

  const userNotifications = notifications.get(userId);
  return unreadOnly
    ? userNotifications.filter((n) => !n.read)
    : userNotifications;
}

// ======================
// NOTIFICATION ROUTES
// ======================

// Get all notifications for user
app.get("/api/notifications", async (req, res) => {
  try {
    const userId = req.session.user?.std_id || "default-user";
    const unreadOnly = req.query.unread === "true";

    const userNotifications = getUserNotifications(userId, unreadOnly);
    res.json({
      success: true,
      count: userNotifications.length,
      notifications: userNotifications,
    });
  } catch (err) {
    console.error("Notification error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Mark notification as read
app.post("/api/notifications/:id/read", async (req, res) => {
  try {
    const userId = req.session.user?.std_id || "default-user";
    const notificationId = parseInt(req.params.id);

    if (markAsRead(userId, notificationId)) {
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, error: "Notification not found" });
    }
  } catch (err) {
    console.error("Mark as read error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Create new notification (for testing)
app.post("/api/notifications", async (req, res) => {
  try {
    const { type, message } = req.body;
    const userId = req.session.user?.std_id;

    if (!userId || !type || !message) {
      return res.status(400).json({
        success: false,
        error: "type and message are required",
      });
    }

    const notification = addNotification(
      userId,
      type,
      message,
      req.body.data || {}
    );

    res.json({ success: true, notification });
  } catch (err) {
    console.error("Create notification error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ======================
// SOCKET.IO INTEGRATION (REAL-TIME)
// ======================

const server = createServer(app);
const io = new Server(server);

io.on("connection", (socket) => {
  console.log("New client connected");

  socket.on("join", (userId) => {
    socket.join(userId);
    console.log(`User ${userId} joined their notification room`);
  });

  socket.on("disconnect", () => {
    console.log("Client disconnected");
  });
});

// Function to send real-time notification
function sendRealTimeNotification(userId, notification) {
  io.to(userId).emit("new_notification", notification);
}

// ======================
// AUTHENTICATION MIDDLEWARE
// ======================

// Middleware to check if user is authenticated
const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
};

// Middleware for registration session
const requireSession = (req, res, next) => {
  console.log("requireSession middleware, session:", req.session);
  if (!req.session.registration_data) {
    console.log("No registration data in session, redirecting to /register");
    return res.redirect("/register");
  }
  next();
};

// ======================
// STATIC PAGES ROUTES
// ======================

// Landing page
app.get(["/", "/first_p"], (req, res) => {
  res.render("first_p.ejs");
});

// Public pages (no login required)
const publicRoutes = ["contact", "about", "service", "privacy"];

// Pages requiring authentication
const authRoutes = [
  "companies",
  "courses",
  "certi-0",
  "cs",
  "cis",
  "ai",
  "bit",
  "cyber",
  "sw",
  "train",
  "home",
  "company1",
  "comp-1",
  "CV",
  "task_std",
  "req",
  "notification",
  "rating",
];

// Set up public routes
publicRoutes.forEach((view) => {
  app.get("/" + view, (req, res) => {
    res.render(`${view}.ejs`);
  });
});

// Set up authenticated routes
authRoutes.forEach((view) => {
  app.get("/" + view, requireAuth, (req, res) => {
    try {
      res.render(`${view}.ejs`, { user: req.session.user });
    } catch (err) {
      console.error(`Error rendering ${view}.ejs:`, err);
      res.status(500).render("error", { message: "Page rendering error" });
    }
  });
});

// ======================
// REGISTRATION & LOGIN ROUTES
// ======================

// Registration routes (GET handlers)
app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/register2", (req, res) => {
  console.log("GET /register2, session:", req.session);
  res.render("register2.ejs");
});

app.get("/register3", requireSession, (req, res) => {
  console.log("GET /register3, session:", req.session);
  res.render("register3.ejs");
});
app.post("/register", async (req, res) => {
  try {
    console.log("POST /register received:", req.body);

    // Defensive check for empty request body
    if (!req.body) {
      throw new Error("Form data is empty");
    }

    // Extract form fields with defaults to prevent undefined
    const {
      username = "",
      std_id = "",
      password = "",
      confirm_password = "",
    } = req.body;

    if (!username || !std_id || !password || !confirm_password) {
      return res.render("register", { error: "All fields are required" });
    }

    if (password !== confirm_password) {
      return res.render("register", { error: "Passwords do not match" });
    }

    const existingUser = await db.query(
      "SELECT * FROM users WHERE std_id = $1",
      [std_id]
    );

    if (existingUser.rows.length > 0) {
      return res.render("register", {
        error: "Student ID is already registered",
      });
    }

    // Initialize session object
    req.session.registration_data = {
      username,
      std_id,
      password,
    };

    req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err);
        return res.status(500).render("error", { message: "Session error" });
      }
      console.log("Redirecting to /register2");
      res.redirect("/register2");
    });
  } catch (err) {
    console.error("Registration error details:", err);
    res.status(500).render("error", {
      message: "Registration failed: " + err.message,
    });
  }
});

// Step 2: Additional information
app.post("/register2", async (req, res) => {
  try {
    console.log("POST /register2 received:", req.body);

    // Get form data from second form
    const { city, university, gpa, gender, specialization } = req.body;

    req.session.registration_data = {
      ...req.session.registration_data,
      city,
      university,
      gpa,
      gender,
      specialization,
    };

    req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err);
        return res.status(500).send("Failed to save session");
      }
      console.log("Redirecting to /register3");
      res.redirect("/register3");
    });
  } catch (err) {
    console.error("Step 2 error:", err);
    res.status(500).send("Error processing your information");
  }
});
app.post("/register3", requireSession, async (req, res) => {
  try {
    const { email } = req.body; // ✅ Add this line

    if (!email) {
      return res.render("register3", { error: "Email is required" });
    }

    // ✅ merge email into session
    req.session.registration_data = {
      ...req.session.registration_data,
      email,
    };

    const {
      username,
      std_id,
      password,
      city,
      university,
      gpa,
      gender,
      specialization,
    } = req.session.registration_data;

    // ✅ log email properly
    console.log("Email received:", email);
    console.log("Session data:", req.session.registration_data);

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Start transaction
    await db.query("BEGIN");

    // Insert into users table
    await db.query(
      `INSERT INTO users (username, std_id, email, password)
       VALUES ($1, $2, $3, $4)`,
      [username, std_id, email, hashedPassword]
    );

    // Insert into students table
    await db.query(
      `INSERT INTO students (std_id, city, university, gpa, gender, specialization)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [std_id, city, university, gpa, gender, specialization]
    );

    await db.query("COMMIT");

    // Create session for the logged-in user
    req.session.user = {
      std_id,
      name: username,
      email,
    };

    // Clear the registration data from the session
    delete req.session.registration_data;

    // Add a welcome notification
    addNotification(
      std_id,
      NOTIFICATION_TYPES.SYSTEM_ALERT,
      "Welcome! Your account has been created successfully."
    );

    // Redirect to home page
    res.redirect("/home");
  } catch (err) {
    await db.query("ROLLBACK");
    console.error("Final registration error:", err);
    res.status(500).render("error", {
      message: "Registration failed: " + err.message,
      error: err, // 👈 ضروري
    });
  }
});

// Login routes
app.get("/login", (req, res) => {
  if (req.session.user) {
    return res.redirect("/profile");
  }
  res.render("login.ejs");
});
app.post("/login", async (req, res) => {
  const { std_id, password } = req.body;

  try {
    // Special case for admin
    if (std_id === "4412106" && password === "Cc!4412106") {
      req.session.user = {
        std_id: "4412106",
        isAdmin: true,
        name: "Admin User",
      };
      return res.redirect("/company1");
    }

    // Check if the user exists
    const result = await db.query("SELECT * FROM users WHERE std_id = $1", [
      std_id,
    ]);

    if (result.rows.length > 0) {
      const user = result.rows[0];

      // Compare the password with the hashed one in the database
      const isMatch = await bcrypt.compare(password, user.password);

      if (isMatch) {
        // Store user data in session
        req.session.user = {
          std_id: user.std_id,
          name: user.username,
          email: user.email,
          isAdmin: user.isAdmin || false, // If 'isAdmin' exists in the DB
        };

        // Add login notification (function needs to be defined properly)
        addNotification(
          user.std_id,
          NOTIFICATION_TYPES.SYSTEM_ALERT,
          "You have successfully logged in"
        );

        // Send real-time login notification (function needs to be defined properly)
        sendRealTimeNotification(user.std_id, {
          type: NOTIFICATION_TYPES.SYSTEM_ALERT,
          message: "You have successfully logged in",
          timestamp: new Date(),
        });

        // Redirect to profile page after successful login
        return res.redirect("/home");
      } else {
        // Password is incorrect
        res.render("login", { error: "Incorrect Password" });
      }
    } else {
      // User not found
      res.render("login", { error: "User not found" });
    }
  } catch (err) {
    console.error("Login error:", err);
    // Error during login process
    res.status(500).render("error", { message: "Login failed", error: err });
  }
});

// Profile routea

app.get("/profile", requireAuth, async (req, res) => {
  try {
    const userSession = req.session.user;
    if (!userSession?.std_id) {
      console.log("⚠️  User not logged in or session expired");
      return res.redirect("/login");
    }

    const stdId = userSession.std_id;
    console.log("📥 Fetching profile for user:", stdId);

    const query = `
  SELECT 
    u.std_id,
    u.username AS name, 
    u.email, 
    s.specialization AS major, 
    s.university, 
    s.gpa
  FROM users u
  LEFT JOIN students s ON u.std_id = s.std_id
  WHERE u.std_id = $1
`;

    const result = await db.query(query, [stdId]);
    const userData = result.rows[0];

    if (!userData) {
      console.log("❌ No user found with std_id:", stdId);
      req.session.destroy();
      return res.redirect("/login");
    }

    const user = {
      std_id: userData.std_id,
      name: userData.name || "Anonymous",
      email: userData.email || "No email registered",
      major: userData.major || "Undeclared",
      university: userData.university || "Not specified",
      gpa: userData.gpa != null ? Number(userData.gpa).toFixed(2) : "N/A",
    };

    console.log("✅ Profile loaded successfully for:", user.name);
    res.render("profile.ejs", { user });
  } catch (err) {
    console.error("❗ Error loading profile:", err);
    res.status(500).render("error", {
      message: "Profile loading failed",
      error: process.env.NODE_ENV === "development" ? err : null,
    });
  }
});
app.get("/train", requireAuth, async (req, res) =>{
  res.redirect("/train");
});


// Logout route
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.status(500).send("Error logging out");
    }
    res.redirect("/login");
  });
});

// Delete account
app.post("/delete-account", requireAuth, async (req, res) => {
  try {
    const result = await db.query("DELETE FROM users WHERE std_id = $1", [
      req.session.user.std_id,
    ]);

    if (result.rowCount > 0) {
      req.session.destroy();
      res.send("Your account has been deleted successfully.");
    } else {
      res.send("Error: Account not found.");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error: " + err.message);
  }
});

// ======================
// EMAIL SERVICES
// ======================

// Email configuration
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "lenabukhalil98@gmail.com",
    pass: "uriw pemd gjmi udkz",
  },
});

// OTP routes
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).send("Email is required!");
  }

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    let otp = Math.floor(100000 + Math.random() * 900000);
    let expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 10);

    if (result.rows.length === 0) {
      const stdId = Math.floor(100000 + Math.random() * 900000);
      const placeholderPassword = "default_password";

      await db.query(
        `INSERT INTO users (email, otp, otp_expires_at, std_id, password)
         VALUES ($1, $2, $3, $4, $5)`,
        [email, otp, expiresAt, stdId, placeholderPassword]
      );
    } else {
      await db.query(
        `UPDATE users SET otp = $1, otp_expires_at = $2 WHERE email = $3`,
        [otp, expiresAt, email]
      );
    }

    await transporter.sendMail({
      from: "lenabukhalil98@gmail.com",
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP code is: ${otp}. It is valid for 10 minutes.`,
    });

    res.status(200).send("OTP sent successfully!");
  } catch (error) {
    console.error("Error:", error.message);
    res.status(500).send(`Failed to send OTP: ${error.message}`);
  }
});

app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).send("Email and OTP are required!");
  }

  try {
    const result = await db.query(
      "SELECT otp, otp_expires_at FROM users WHERE email = $1",
      [email]
    );

    const userRecord = result.rows[0];

    if (!userRecord) {
      return res.status(404).send("User not found.");
    }

    const currentTime = new Date();
    if (userRecord.otp !== otp) {
      return res.status(400).send("Invalid OTP.");
    }

    if (new Date(userRecord.otp_expires_at) < currentTime) {
      return res.status(400).send("OTP has expired.");
    }

    // Create session for the user
    const userData = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (userData.rows.length > 0) {
      const user = userData.rows[0];
      req.session.user = {
        id: user.id,
        std_id: user.std_id,
        name: user.username,
        email: user.email,
      };
    }

    res.redirect("/home");
  } catch (error) {
    console.error("Error:", error.message);
    res.status(500).send("Failed to verify OTP.");
  }
});

// ======================
// COMPANY DATA ROUTES
// ======================

// Sample application data
const applications = [
  {
    id: 1,
    name: "Lana Abu-Hmaid",
    email: "lana@example.com",
    cv_url: "/cv_files/cv1.pdf",
    status: "Pending",
  },
  {
    id: 2,
    name: "Ahmad Ali",
    email: "ahmad@example.com",
    cv_url: "/cv_files/cv2.pdf",
    status: "Accepted",
  },
];

// API for retrieving training applications
app.get("/company/:companyId/applications", requireAuth, (req, res) => {
  res.json(applications);
});

// Route for viewing student CVs
app.use("/cv_files", express.static(path.join(__dirname, "cv_files")));

// ======================
// ERROR HANDLING
// ======================

// 404 handler
app.use((req, res, next) => {
  res.status(404).render("error", { message: "Page not found" });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).render("error", {
    message: "Server error",
    error: process.env.NODE_ENV === "development" ? err : {},
  });
});

// ======================
// SERVER STARTUP
// ======================

server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// Graceful shutdown
process.on("SIGINT", async () => {
  console.log("Closing server...");
  await db.end();
  server.close();
  process.exit();
});
