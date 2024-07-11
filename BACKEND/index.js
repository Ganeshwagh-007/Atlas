import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import session from "express-session";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const hostname='0.0.0.0';
const port = 3000;
const saltRounds = 10;

// Initialize PostgreSQL client
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

// Middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("../FRONTEND/public"));
app.use(passport.initialize());
app.use(passport.session());

// Define routes
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});


app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query(`
        SELECT secretstable.id, secretstable.secret_text, users.id AS user_id
        FROM secretstable
        INNER JOIN users ON secretstable.user_id = users.id
        WHERE users.email = $1`, [req.user.email]);
        const secrets = result.rows;
      res.render("secrets.ejs", { secrets });
    } catch (err) {
      console.error("Error fetching secrets:", err);
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.redirect("/login");
  }
});


app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);



app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
}));

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
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
            if (err) {
              console.error("Error logging in user:", err);
            } else {
              res.redirect("/secrets");
            }
          });
        }
      });
    }
  } catch (err) {
    console.error("Error registering user:", err);
    res.status(500).send("Internal Server Error");
  }
});


app.post("/submit", async (req, res) => {
  const submittedSecret = req.body.secret;
  try {
    const result = await db.query(`INSERT INTO secretstable (secret_text, user_id) VALUES ($1, $2)`, [
      submittedSecret,
      req.user.id, 
    ]);
    res.redirect("/secrets");
  } catch (err) {
    console.error("Error submitting secret:", err);
    res.status(500).send("Internal Server Error");
  }
});


app.post('/delete', async (req, res) => {
  const id = req.body.deleteItemId;
  console.log('Received deleteItemId:', id);

  // Validate input
  if (!id || isNaN(id)) {
    console.log('Invalid id received:', id);
    return res.status(400).send('Invalid id');
  }

  try {
    await db.query('DELETE FROM secretstable WHERE id = $1', [id]);
    res.redirect('/secrets');
  } catch (err) {
    console.log(err);
    res.status(500).send('Internal Server Error');
  }
});



// Local strategy for passport
passport.use(
  "local",
  new LocalStrategy({ passReqToCallback: true }, async (req, username, password, cb) => {
    try {
      const email = req.session.selectedAccount || username;
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [email]);
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
      console.error("Error authenticating user:", err);
      return cb(err);
    }
  })
);

// Google OAuth2 Strategy
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      passReqToCallback: true,
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (req, accessToken, refreshToken, profile, cb) => {
      try {
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
        console.error("Error creating Google user:", err);
        return cb(err);
      }
    }
  )
);

// Serialize and deserialize user
passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    cb(null, result.rows[0]);
  } catch (err) {
    console.error("Error deserializing user:", err);
    cb(err);
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
