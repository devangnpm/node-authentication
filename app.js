/////// app.js

const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const path = require("path");
const bcryptjs = require("bcryptjs");


// creating a new pool of connection to Postgres with the db credentials
const pool = new Pool({
  user: "devang101", // Database user
  host: "localhost", // Database host
  database: "postgres", // Database name
  password: "pass123", // User password
  port: 5432, // Default PostgreSQL port
});

//creating an express application here
const app = express();

// setting the views path and view engine to ejs
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");


app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => res.render("index", { user: req.body }));

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", async (req, res, next) => {
  try {
    bcryptjs.hash(req.body.password, 10, async (err, hashedPassword) => {
      if (err) return next(err);  // handling hashing error here

      await pool.query(
        "INSERT INTO users (username,email, hashedPassword) VALUES ($1, $2, $3)",
        [req.body.username, req.body.email, hashedPassword]
      );
    });
    res.redirect("/");
  } catch (err) {
    return next(err); // handling query error here
  }
});

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
      const user = rows[0];

      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      if (user.hashedPassword !== password) {
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch(err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = rows[0];

    done(null, user);
  } catch(err) {
    done(err);
  }
});



app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/log-in",
  })
);

app.get("/log-in", (req, res) => res.render("index"));


app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});


app.listen(3000, () => console.log("app listening on port 3000!"));
