const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const UserModel = require("./models/User");
const router = express.Router();

const app = express();

app.use(express.json());

app.use(cookieParser());

mongoose.connect("mongodb://127.0.0.1:27017/hi");

app.use(
  cors({
    origin: "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.options("*", cors());

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    console.log(" No token found in cookies");
    return res.status(403).json({ error: "Token missing" });
  }

  jwt.verify(token, "jwt-secret-key", (err, decoded) => {
    if (err) {
      console.log(" Invalid token:", err.message);
      return res.status(403).json({ error: "Invalid token" });
    }

    req.user = decoded;
    next();
  });
};

// Admin Dashboard Route
app.get("/dashboard", verifyUser, (req, res) => {
  if (req.user.role !== "superadmin") return res.json({ error: "Not authorized" });
  res.json("superAdmin Access Granted");
});

// User Dashboard Route
app.get("/user-dashboard", verifyUser, (req, res) => {
  if (req.user.role !== "admin") return res.json({ error: "Not authorized" });
  res.json("admin Access Granted");
});


app.post("/signup", (req, res) => {
  const { name, email, password, role } = req.body;
  bcrypt
    .hash(password, 10)
    .then((hash) => {
      UserModel.create({
        name,
        email,
        password: hash,
        role: role || "user",
        status: "active", 
      })
        .then(() =>
          res.json({
            status: "success",
            message: "Signup successful! Waiting for admin approval.",
          })
        )
        .catch((err) => res.json(err));
    })
    .catch((err) => res.json(err));
});



app.post("/login", (req, res) => {
  const { email, password } = req.body;
  UserModel.findOne({ email }).then((user) => {
    if (!user) return res.json({ error: "No record exists" });

    if (user.status !== "active") {
      return res.json({
        error: "Account inactive. Please wait for admin approval.",
      });
    }

    bcrypt.compare(password, user.password, (err, response) => {
      if (!response) return res.json({ error: "Incorrect password" });

      const token = jwt.sign(
        { email: user.email, role: user.role },
        "jwt-secret-key",
        { expiresIn: "2d" }
      );
      res.cookie("token", token, { httpOnly: true });
      return res.json({ status: "success", role: user.role });
    });
  });
});

// Logout Route
app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ status: "Logged out" });
});

app.get("/admin", verifyUser, async (req, res) => {
  console.log("Request received at /users"); // Debugging log

  if (!req.user || req.user.role !== "superadmin") {
    console.log("Unauthorized access attempt"); // Debugging log
    return res.status(403).json({ error: "Not authorized" });
  }

  try {
    const users = await UserModel.find({}, "name email role createdAt");
    res.json(users);
  } catch (err) {
    console.error("Database error:", err); // Debugging log
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

// Update user status
app.put("/admin/:id/status", verifyUser, async (req, res) => {
  if (req.user.role !== "superadmin")
    return res.status(403).json({ error: "Not authorized" });

  try {
    await UserModel.findByIdAndUpdate(req.params.id, {
      status: req.body.status,
    });
    res.json({ status: "updated" });
  } catch (error) {
    res.status(500).json({ error: "Failed to update status" });
  }
});

app.delete("/admin/:id", async (req, res) => {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ error: "Invalid user ID" });
  }

  try {
    console.log("Deleting user with ID:", req.params.id); // Debugging log

    const user = await UserModel.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ error: "Failed to delete user" });
  }
});


/*app.get("/admin/:id", verifyUser, async (req, res) => {
  if (!req.user || req.user.role !== "superadmin") {
    return res.status(403).json({ error: "Not authorized" });
  }

  try {
    const admin = await UserModel.findById(req.params.id);
    if (!admin) return res.status(404).json({ error: "Admin not found" });

    res.json(admin);
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "Failed to fetch admin details" });
  }
});*/

app.get("/admin/:id", verifyUser, async (req, res) => {
  console.log("Admin ID requested:", req.params.id); // Debugging log

  if (!req.user || req.user.role !== "superadmin") {
    return res.status(403).json({ error: "Not authorized" });
  }

  try {
    const admin = await UserModel.findById(req.params.id);
    if (!admin) return res.status(404).json({ error: "Admin not found" });

    console.log("Admin found:", admin); // Debugging log
    res.json(admin);
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "Failed to fetch admin details" });
  }
});





app.put("/admin/:id", verifyUser, async (req, res) => {
  if (req.user.role !== "superadmin")
    return res.status(403).json({ error: "Not authorized" });

  try {
    const updatedUser = await UserModel.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    if (!updatedUser) return res.status(404).json({ error: "admin not found" });

    res.json({ status: "admin updated", user: updatedUser });
  } catch (error) {
    console.error("Error updating admin:", error);
    res.status(500).json({ error: "Failed to update admin" });
  }
});



app.get("/admin", async (req, res) => {
  try {
    let { page, limit, priority } = req.query;

    // Convert query params to numbers
    page = parseInt(page) || 0; // Default to page 0
    limit = parseInt(limit) || 3; // Default to limit 3

    console.log(
      `Fetching users - Page: ${page}, Limit: ${limit}, Priority: ${priority}`
    );

    // Fetch users from MongoDB with pagination
    const users = await User.find()
      .skip(page * limit) // Skip records for pagination
      .limit(limit); // Limit number of records

    const totalUsers = await User.countDocuments();

    res.json({
      users,
      totalUsers,
      currentPage: page,
      totalPages: Math.ceil(totalUsers / limit),
    });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

router.get("/users", async (req, res) => {
  try {
    let { page = 0, limit = 3, priority } = req.query;
    page = parseInt(page);
    limit = parseInt(limit);

    // Optional: Filter users by priority (e.g., "low")
    let filter = {};
    if (priority) {
      filter.priority = priority;
    }

    // Fetch paginated users
    const users = await User.find(filter)
      .skip(page * limit) // Skip users based on page number
      .limit(limit); // Limit results per page

    // Get total count for correct pagination
    const totalUsers = await User.countDocuments(filter);

    res.json({ users, totalUsers });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/admin-users", verifyUser, async (req, res) => {
  if (!req.user || req.user.role !== "superadmin") {
    return res.status(403).json({ error: "Not authorized" }); // THIS LINE TRIGGERS 403 ERROR
  }

  try {
    const adminUsers = await UserModel.find({ role: "admin" });
    res.json(adminUsers);
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "Failed to fetch admin users" });
  }
});

app.get("/admin/:id/trainers", verifyUser, async (req, res) => {
  if (!req.user || (req.user.role !== "superadmin" && req.user.role !== "admin")) {
    return res.status(403).json({ error: "Not authorized" });
  }
  

  try {
    const trainers = await UserModel.find({ parent_id: req.params.id, role: "trainer" });

    res.json(trainers);
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "Failed to fetch trainers" });
  }
});




module.exports = router;

app.listen(5006, () => console.log("Server running on port 5006"));
