const mongoose = require("mongoose");

const InvestmentSchema = new mongoose.Schema({
  investor: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  campaign: { type: mongoose.Schema.Types.ObjectId, ref: "Campaign", required: true },
  amount: { type: Number, required: true },
  tokens: { type: Number, required: true, default: 0 },

  blockchainCampaignId: { type: String }, // Stores the hex ID
  tokenId: { type: Number, default:0 },
  
  // Token details snapshot at time of investment
  tokenDetails: {
    name: { type: String, required: true },
    symbol: { type: String, required: true },
    type: { type: String, required: true },
    value: { type: Number, required: true },
    metadata: { type: mongoose.Schema.Types.Mixed }
  },
  
  transactionHash: { type: String},
  timeCreated: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Investment", InvestmentSchema);
