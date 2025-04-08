const express = require("express");
const Investment = require("../models/Investment.model.js");
const router = express.Router();

// Create a new investment
router.post("/", async (req, res) => {
  const { investor, campaign, amount, transactionHash } = req.body;

  try {
    const investment = new Investment({ investor, campaign, amount, transactionHash });
    await investment.save();
    res.status(201).json(investment);
  } catch (err) {
    res.status(500).json({ message: "Server Error" });
  }
});

// Fetch all investments for a campaign
router.get("/:campaignId", async (req, res) => {
  try {
    const investments = await Investment.find({ campaign: req.params.campaignId });
    res.json(investments);
  } catch (err) {
    res.status(500).json({ message: "Server Error" });
  }
});

module.exports = router;
