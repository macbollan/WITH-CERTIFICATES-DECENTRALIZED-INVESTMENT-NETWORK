const express = require("express");
const passport = require("passport");
const bcrypt = require("bcryptjs");
const User = require("../models/User.model");
const upload = require("../middleware/upload"); // Import upload middleware
const router = express.Router();

// Register Route
router.get("/register", (req, res) => {
  res.render("register"); // Renders the register.ejs view
});

router.post("/register", upload, async (req, res) => {
  const { username, email, password, age, gender, bio } = req.body;
  let profilePicture = req.file ? "/uploads/" + req.file.filename : null; // Save image path relative to public folder

  try {
    let user = await User.findOne({ email });
    if (user) {
      req.flash("error_msg", "User already exists");
      return res.redirect("/register");
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({
      username,
      email,
      password: hashedPassword,
      age,
      gender,
      bio,
      profilePicture,
    });

    await user.save();
    req.flash("success_msg", "You are now registered and can log in");
    res.redirect("/login");
  } catch (err) {
    req.flash("error_msg", "Server error");
    res.redirect("/register");
  }
});

// Login Route
router.get("/login", (req, res) => {
  res.render("login"); // Renders the login.ejs view
});

router.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/login",
  failureFlash: true,
  successFlash: "Welcome back!",
}));

// Logout Route
router.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

module.exports = router;
