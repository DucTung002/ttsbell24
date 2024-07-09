const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const JwtStrategy = require("passport-jwt").Strategy;
const extractJwt = require("passport-jwt").ExtractJwt;
const expressSession = require("express-session");
const flash = require("connect-flash");
const { body, validationResult } = require('express-validator');

const app = express();
const port = 3000;

mongoose.connect("mongodb://localhost:27017/dbtest", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema(
  {
    _id: String,
    name: String,
    email: String,
    address: String,
    phone: String,
  },
  { versionKey: false }
);

const accountSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
    },
    password: String,
  },
  { versionKey: false }
);

const User = mongoose.model("User", userSchema);
const Account = mongoose.model("Account", accountSchema);

app.use(bodyParser.json());
app.use(expressSession({ secret: "tungct2k2", resave: true, saveUninitialized: true }));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await Account.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// Sử dụng JWT strategy
passport.use(new JwtStrategy(
  {
    jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: 'tungct2k2',
  },
  (jwtPayload, done) => {
    Account.findById(jwtPayload.id, (err, user) => {
      if (err) {
        return done(err, false);
      }
      if (user) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    });
  }
));

const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  req.flash('error', 'You need to log in first.');
  res.redirect("/");
};

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "/public/login.html"));
});

app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "/public/register.html"));
});

app.post("/users", async (req, res) => {
  try {
    const { _id, name, email, address, phone } = req.body;
    const newUser = new User({ _id, name, email, address, phone });
    const savedUser = await newUser.save();
    res.json(savedUser);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.get("/users", async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get("/users/:uid", async (req, res) => {
  try {
    const user = await User.findOne({ _id: req.params.uid });
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.put("/users/:uid", async (req, res) => {
  try {
    const updatedUser = await User.findOneAndUpdate(
      { _id: req.params.uid },
      req.body,
      { new: true }
    );
    if (updatedUser) {
      res.json(updatedUser);
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.delete("/users/:uid", async (req, res) => {
  try {
    const deletedUser = await User.findOneAndDelete({ _id: req.params.uid });
    if (deletedUser) {
      res.json({ message: "User deleted successfully" });
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post("/register", [
  body('username')
    .isLength({ min: 5 }).withMessage('Username must be at least 5 characters')
    .isLength({ max: 20 }).withMessage('Username must be at most 20 characters'),
  body('password')
    .isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
    .isLength({ max: 30 }).withMessage('Password must be at most 30 characters'),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const errorMessages = errors.array().map(error => error.msg);
      return res.status(400).json({ errors: errorMessages });
    }

    const { username, password } = req.body;
    const existingAccount = await Account.findOne({ username });
    if (existingAccount) {
      req.flash('error', 'Username already exists.');
      return res.status(400).json({ message: "Username already exists" });
    }

    const newAccount = new Account({ username, password });
    const savedAccount = await newAccount.save();
    res.json(savedAccount);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.post("/login", async (req, res, next) => {
  const { username, password } = req.body;

  try {
    const user = await Account.findOne({ username });

    if (!user || user.password !== password) {
      return res.status(401).json({
        message: 'Authentication failed',
        user: user
      });
    }

    const token = jwt.sign({ id: user._id }, 'tungct2k2');
    return res.json({ success: true, token, username: user.username, redirect: '/dashboard' });

  } catch (err) {
    return res.status(500).json({ message: 'Internal Server Error', error: err });
  }
});

app.get("/dashboard", passport.authenticate('jwt', { session: false }), (req, res) => {
  res.send("Welcome to the administration page, " + req.user.username + "!");
});

app.use(express.static("public"));

app.listen(port, () => {
  console.log(`Server is running: http://localhost:${port}`);
});
