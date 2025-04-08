const mongoose = require("mongoose");

const CampaignSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  goalAmount: { type: Number, required: true },
  amountRaised: { type: Number, default: 0 },
  status: { type: String, enum: ["active", "funded", "closed"], default: "active" },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
});

module.exports = mongoose.model("Campaign", CampaignSchema);
