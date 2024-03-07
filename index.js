// Importing required modules
import express from "express"; // Express.js framework for handling HTTP requests
import bodyParser from "body-parser"; // Middleware to parse request bodies
import pg from "pg"; // PostgreSQL client
import bcrypt from "bcrypt"; // Library for hashing passwords
import passport from "passport"; // Authentication middleware for Node.js
import { Strategy } from "passport-local"; // Local authentication strategy for Passport
import GoogleStrategy from "passport-google-oauth2"; // Google OAuth2 authentication strategy for Passport
import session from "express-session"; // Middleware for managing user sessions
import env from "dotenv"; // Module to load environment variables from a .env file

// Initialize Express app
const app = express();
const port = 3000;

// Constants
const saltRounds = 10;

// Load environment variables from .env file
env.config();

// Middleware setup
app.use(
  session({
    secret: process.env.SESSION_SECRET, // Session secret key
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use(express.static("public")); // Serve static files

// Initialize Passport and session management
app.use(passport.initialize());
app.use(passport.session());

// PostgreSQL client setup
const db = new pg.Client({
  user: process.env.PG_USER, // PostgreSQL username
  host: process.env.PG_HOST, // PostgreSQL host
  database: process.env.PG_DATABASE, // PostgreSQL database name
  password: process.env.PG_PASSWORD, // PostgreSQL password
  port: process.env.PG_PORT, // PostgreSQL port
});
db.connect(); // Connect to the PostgreSQL database

// Routes

// Home page route
app.get("/", (req, res) => {
  res.render("home.ejs"); // Render home page template
});

// Login page route
app.get("/login", (req, res) => {
  res.render("login.ejs"); // Render login page template
});

// Register page route
app.get("/register", (req, res) => {
  res.render("register.ejs"); // Render register page template
});

// Logout route
app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// Secrets page route
app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    const result = await db.query("SELECT secret FROM users WHERE id = $1", [req.user.id]);
    res.render("secrets.ejs", { secret: result.rows[0].secret }); // Render secrets page template with user's secret
  } else {
    res.redirect("/login");
  }
});

// Submit page route
app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs"); // Render submit page template
  } else {
    res.redirect("/login");
  }
});

// Google authentication route
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

// Google authentication callback route
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// Login form submission route
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// User registration route
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

// Submit secret route
app.post("/submit", async (req, res) => {
  const secret = req.body.secret;

  try {
    if (req.isAuthenticated()) {
      await db.query("UPDATE users SET secret = $1 WHERE id = $2", [secret, req.user.id]);
      console.log(`Secret submitted : ${secret}`);
      res.redirect("/secrets");
    } else {
      res.redirect("/login");
    }
  } catch (error) {
    console.error("Error submitting secret:", err);
    res.status(500).send("Error submitting secret");
  }
});

// Passport local authentication strategy setup
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

// Passport Google OAuth2 strategy setup
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID, // Google OAuth2 client ID
      clientSecret: process.env.GOOGLE_CLIENT_SECRET, // Google OAuth2 client secret
      callbackURL: "http://localhost:3000/auth/google/secrets", // Callback URL for Google authentication
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo", // Google user profile URL
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

// Passport user serialization and deserialization
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});