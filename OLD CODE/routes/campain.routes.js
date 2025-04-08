const express = require("express");
const Campaign = require("../models/Campain.model.js");
const router = express.Router();

// Create a new campaign
router.post("/", async (req, res) => {
  const { title, description, goalAmount, owner } = req.body;

  try {
    const campaign = new Campaign({ title, description, goalAmount, owner });
    await campaign.save();
    res.status(201).json(campaign);
  } catch (err) {
    res.status(500).json({ message: "Server Error" });
  }
});

// Fetch all campaigns
router.get("/", async (req, res) => {
  try {
    const campaigns = await Campaign.find();
    res.json(campaigns);
  } catch (err) {
    res.status(500).json({ message: "Server Error" });
  }
});

module.exports = router;
