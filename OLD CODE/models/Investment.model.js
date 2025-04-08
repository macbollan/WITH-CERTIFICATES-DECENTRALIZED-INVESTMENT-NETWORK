const mongoose = require("mongoose");

const InvestmentSchema = new mongoose.Schema({
  investor: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  campaign: { type: mongoose.Schema.Types.ObjectId, ref: "Campaign" },
  amount: { type: Number, required: true },
  transactionHash: { type: String, required: true },
});

module.exports = mongoose.model("Investment", InvestmentSchema);
