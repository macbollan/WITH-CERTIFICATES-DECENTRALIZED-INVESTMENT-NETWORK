const mongoose = require("mongoose");
const passportLocalMongoose = require("passport-local-mongoose");

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
  },
  surname: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  phone: {
    type: String,
    required: true,
    unique: true,
  },
  address: {
    type: String,
    required: true,
  },
  password: {
    type: String,
  },
  age: {
    type: Number,
    required: true,
  },
  gender: {
    type: String,
    enum: ["Male", "Female"],
    required: true,
  },
  bio: {
    type: String,
    required: true,
  },
  profilePicture: {
    type: String,
    default: null, // Stores the image path relative to public folder
  },
  otherPictures: [String],

  walletAddress: {
    type: String,
    validate: {
      validator: v => /^0x[a-fA-F0-9]{40}$/.test(v),
      message: 'Invalid Ethereum address'
    }
  },
  fiatBalance: { type: Number, default: 0 },
  
  kycStatus: {
    type: String,
    enum: ['unverified', 'pending', 'verified'],
    default: 'unverified'
  },
  kycDocuments: [{
    filename: String,       // e.g. /uploads/kyc_docs/1234-id.pdf
    originalName: String    // e.g. Passport_ID.pdf
  }],

  dateCreated: {
    type: Date,
    default: Date.now
  },

  isBanned: { type: Boolean, default: false }

  
});

UserSchema.plugin(passportLocalMongoose);
module.exports = mongoose.model("User", UserSchema);
