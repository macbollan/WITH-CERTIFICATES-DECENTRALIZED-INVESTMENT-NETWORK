const mongoose = require('mongoose');

const withdrawalRequestSchema = new mongoose.Schema({
  campaign: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign', required: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amountRequested: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  requestedAt: { type: Date, default: Date.now },
  processedAt: Date
});

module.exports = mongoose.model("WithdrawalRequest", withdrawalRequestSchema);
