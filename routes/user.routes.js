const express = require("express");
const { isAuthenticated } = require("../middleware/authMiddleware");
const User = require("../models/User.model");

const router = express.Router();

// Profile Route
router.get("/profile", isAuthenticated, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.render("profile", { user }); // Renders the profile.ejs view
});

module.exports = router;
