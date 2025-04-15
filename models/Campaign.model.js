const mongoose = require("mongoose");

const CampaignSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  image: { type: String},
  goalAmount: { type: Number, required: true },
  
  // Token Configuration
  tokenType: { 
    type: String, 
    enum: ["profit", "ownership", "rewards", "hybrid"], 
    required: true,
    default: "profit"
  },
  tokenName: { type: String, required: true },
  tokenSymbol: { type: String, required: true, maxlength: 8 },
  totalTokens: { type: Number, required: true },
  
  // Token-Specific Fields

  tokenContractAddress: { type: String },
  tokenName: { type: String, required: true },
  tokenSymbol: { type: String, required: true },
  tokenType: {
      type: String,
      enum: ["profit", "ownership", "rewards", "hybrid"],
      required: true
  },
  tokenMetadata: { type: mongoose.Schema.Types.Mixed },
  
  // Existing fields
  amountRaised: { type: Number, default: 0 },
  status: { type: String, enum: ["active", "funded", "closed"], default: "active" },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  investors: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  investments: [{ type: mongoose.Schema.Types.ObjectId, ref: "Investment" }],
  timeCreated: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Campaign", CampaignSchema);

