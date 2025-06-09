const mongoose = require("mongoose");

const CampaignSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  image: { type: String },
  goalAmount: { type: Number, required: true },

  // Token Configuration
  tokenType: {
    type: String,
    enum: ["profit", "ownership", "rewards", "hybrid"],
    required: true
  },
  tokenName: { type: String, required: true },
  tokenSymbol: { type: String, required: true, maxlength: 8 },
  totalTokens: { type: Number, required: true },
  tokenContractAddress: { type: String },
  tokenMetadata: { type: mongoose.Schema.Types.Mixed },

  // Campaign Financials
  amountRaised: { type: Number, default: 0 },
  status: {
    type: String,
    enum: ["active", "funded", "closed", "banned", "rejected"],
    default: "active"
  },

  // Owner and Investments
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  investors: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  investments: [{ type: mongoose.Schema.Types.ObjectId, ref: "Investment" }],
  timeCreated: { type: Date, default: Date.now },

  // Documents
  investorDocuments: [{
    filename: String,
    originalName: String
  }],

  // Approval Flags
  isApproved: { type: Boolean, default: false },
  isRejected: { type: Boolean, default: false },

  // Ratings
  ratings: {
    type: [{
      user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      role: { type: String, enum: ['investor', 'analyst'], default: 'investor' },
      riskScore: { type: Number, min: 1, max: 5 },
      executionScore: { type: Number, min: 1, max: 5 },
      comment: String,
      date: { type: Date, default: Date.now }
    }],
    default: []
  },

  // Withdrawal Info
  withdrawalStatus: {
    type: String,
    enum: ['not_requested', 'pending', 'approved', 'rejected', 'paid'],
    default: 'not_requested'
  },
  withdrawalRequestedAt: Date,
  withdrawalProcessedAt: Date,
  payoutWallet: { type: String }
});

module.exports = mongoose.model("Campaign", CampaignSchema);
