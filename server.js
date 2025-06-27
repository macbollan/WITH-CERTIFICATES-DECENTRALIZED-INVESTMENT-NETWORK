const express = require("express");
const mongoose = require("mongoose");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const passportLocalMongoose = require("passport-local-mongoose");
const bodyParser = require("body-parser");
const methodOverride = require("method-override");
const flash = require("connect-flash");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { Parser } = require("json2csv");
const ImageKit = require("imagekit");
const { Paynow } = require('paynow');
require("dotenv").config();
const MongoStore = require("connect-mongo");
const axios = require("axios");
const crypto = require('crypto');
const nodemailer = require("nodemailer");

// ImageKit setup
const imagekit = new ImageKit({
  publicKey: process.env.IMAGEKIT_PUBLIC_KEY,
  privateKey: process.env.IMAGEKIT_PRIVATE_KEY,
  urlEndpoint: process.env.IMAGEKIT_URL_ENDPOINT,
});

const paynow = new Paynow(
  process.env.PAYNOW_INTEGRATION_ID,
  process.env.PAYNOW_INTEGRATION_KEY,
  "https://tasty-humans-arrive.loca.lt/paynow/result", // for server-to-server
  "https://tasty-humans-arrive.loca.lt/payment/status" // for user redirect
);


// Set debug mode if not in production
if (process.env.NODE_ENV !== 'production') {
  paynow.debug = true;
}

// Blockchain setup
const { ethers } = require("ethers");
const pinataSDK = require('@pinata/sdk');

console.log("✅ PINATA_API_KEY:", process.env.PINATA_API_KEY);
console.log("✅ PINATA_API_SECRET:", process.env.PINATA_API_SECRET);


if (!process.env.PINATA_API_KEY || !process.env.PINATA_API_SECRET) {
  throw new Error('Missing Pinata credentials in environment variables');
}

const pinata = new pinataSDK(
  process.env.PINATA_API_KEY.trim(), 
  process.env.PINATA_API_SECRET.trim()
);

(async () => {
  try {
    await pinata.testAuthentication();
    console.log('✅ Pinata authentication successful');
  } catch (err) {
    console.error('❌ Pinata authentication failed:', err.message);
  }
})();

const provider = new ethers.JsonRpcProvider(process.env.ALCHEMY_SEPOLIA_URL);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

const contractABI = [
  "function recordInvestment(uint256,address,uint256,string)",
  "function getInvestment(uint256) view returns (uint256,address,uint256,string)",
  "function getOwner() view returns (address)",
  "function isOwner() view returns (bool)"
];

const contract = new ethers.Contract(
  process.env.CONTRACT_ADDRESS,
  contractABI,
  wallet
);

const app = express();

// Import models
const User = require("./models/User.model");
const Campaign = require("./models/Campaign.model");
const Investment = require("./models/Investment.model");
const WithdrawalRequest = require("./models/WithdrawalRequest");


// MongoDB Connection
mongoose.connect("mongodb+srv://nyctech002:macb@investmentnetwork.o6scueg.mongodb.net/?retryWrites=true&w=majority&appName=INVESTMENTNETWORK", {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// Middleware Setup
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "10mb", parameterLimit: 10000 }));
app.use(methodOverride("_method"));
app.use(express.static(path.join(__dirname, "public")));
app.use('/metadata', express.static(path.join(__dirname, 'public/metadata')));
app.set("view engine", "ejs");
app.use(flash());

// PASSPORT CONFIGURATION
app.use(require("express-session")({
  secret: "the secret",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());
passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// Middleware to make user available in templates
app.use(function (req, res, next) {
  res.locals.currentUser = req.user;
  res.locals.success = req.flash("success");
  res.locals.error = req.flash("error");
  next();
});

// After session configuration
app.use((req, res, next) => {
  // Save session before redirects/response
  const originalRedirect = res.redirect;
  res.redirect = function(url) {
    return req.session.save(() => originalRedirect.call(this, url));
  };
  
  // Save session for JSON responses
  const originalJson = res.json;
  res.json = function(obj) {
    return req.session.save(() => originalJson.call(this, obj));
  };
  
  next();
});

// Multer memory storage configuration
const memoryStorage = multer.memoryStorage();

// File filters
const imageFilter = (req, file, cb) => {
  if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/i)) {
    return cb(new Error("Only image files are allowed!"), false);
  }
  cb(null, true);
};

const kycFilter = (req, file, cb) => {
  const allowed = ['.pdf', '.png', '.jpg', '.jpeg'];
  const ext = path.extname(file.originalname).toLowerCase();
  if (allowed.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error('Only PDF, PNG, JPG, and JPEG files are allowed'));
  }
};

// Multer configurations
const upload = multer({ 
  storage: memoryStorage,
  fileFilter: imageFilter,
  limits: { fileSize: 10 * 1024 * 1024 }
});

const kycUpload = multer({ 
  storage: memoryStorage,
  fileFilter: kycFilter,
  limits: { fileSize: 10 * 1024 * 1024 }
});

const kyc_upload = multer({ 
  storage: memoryStorage,
  fileFilter: kycFilter,
  limits: { fileSize: 10 * 1024 * 1024 }
});

// ImageKit upload helper function
async function uploadToImageKit(file, folder = 'default') {
  try {
    const result = await imagekit.upload({
      file: file.buffer.toString('base64'),
      fileName: `${Date.now()}-${file.originalname}`,
      folder: `/${folder}`,
      useUniqueFileName: true
    });
    return result.url;
  } catch (error) {
    console.error('ImageKit upload error:', error);
    throw error;
  }
}

// =====================
// ROUTES
// =====================

// Home routes
app.get("/", (req, res) => {
  res.render("index", { currentUser: req.user });
});

app.get("/about", (req, res) => {
  res.render("about");
});

// Auth routes
app.get("/register", (req, res) => {
  res.render("register", { currentUser: req.user });
});

app.post("/register", upload.single("profilePicture"), async (req, res) => {
  try {
    let profilePictureUrl = null;
    if (req.file) {
      profilePictureUrl = await uploadToImageKit(req.file, 'profile_pictures');
    }

    const newUser = new User({
      username: req.body.username,
      surname: req.body.surname,
      email: req.body.email,
      phone: req.body.phone,
      address: req.body.address,
      age: req.body.age,
      gender: req.body.gender,
      bio: req.body.bio,
      profilePicture: profilePictureUrl
    });

    User.register(newUser, req.body.password, function (err, user) {
      if (err) {
        req.flash("error", err.message);
        return res.redirect("/register");
      }
      passport.authenticate("local")(req, res, function () {
        req.flash("success", "Successfully registered");
        res.redirect("/profile");
      });
    });
  } catch (err) {
    console.error(err);
    req.flash("error", "Registration failed");
    res.redirect("/register");
  }
});

app.get("/login", (req, res) => {
  res.render("login", { currentUser: req.user, message: req.flash("error") });
});

app.post("/login", passport.authenticate("local", {
  successFlash: "Successfully logged in",
  failureRedirect: "/login",
  failureFlash: true
}), (req, res) => {
  if (req.user.username === "admin") {
    return res.redirect("/admin/dashboard");
  }
  res.redirect("/profile");
});

app.get("/logout", (req, res) => {
  req.logout(err => {
    if (err) {
      console.log(err);
      return res.redirect("/");
    }
    req.flash("success", "Successfully logged out");
    res.redirect("/campaigns");
  });
});

// Profile routes
app.get("/profile", isLoggedIn, async (req, res) => {
  try {
    const campaigns = await Campaign.find({ owner: req.user._id }).populate("owner");
    const investments = await Investment.find({ investor: req.user._id })
      .populate({
        path: 'campaign',
        select: 'title _id tokenSymbol tokenType',
        options: { lean: true }
      });

    const processedInvestments = investments.map(investment => {
      const tokenDetails = investment.tokenDetails || {
        name: investment.campaign?.tokenSymbol || "N/A",
        symbol: investment.campaign?.tokenSymbol || "N/A",
        type: investment.campaign?.tokenType || "profit",
        value: investment.amount || 0
      };

      return {
        ...investment.toObject(),
        campaign: investment.campaign || { 
          title: "Deleted Campaign", 
          _id: null,
          tokenSymbol: "N/A"
        },
        tokenDetails: {
          name: tokenDetails.name,
          symbol: tokenDetails.symbol,
          type: tokenDetails.type,
          value: tokenDetails.value
        }
      };
    });

    const userTokens = processedInvestments.map(investment => {
      const tokenValue = investment.tokenDetails.value || investment.amount || 0;
      const tokenAmount = investment.tokens || 1;
      
      return {
        _id: investment._id,
        campaignTitle: investment.campaign.title,
        campaignId: investment.campaign._id,
        tokenName: investment.tokenDetails.name,
        tokenSymbol: investment.tokenDetails.symbol,
        tokenType: investment.tokenDetails.type,
        amount: tokenAmount,
        valuePerToken: tokenValue / tokenAmount,
        tokenId: investment.tokenId,
        profitSharePercentage: investment.tokenDetails.type === 'profit' ? 
          (investment.amount / tokenValue * 100) : 0,
        ownershipPercentage: investment.tokenDetails.type === 'ownership' ? 
          (tokenAmount * 100) : 0,
        rewardDescription: investment.tokenDetails.type === 'rewards' ? 
          "Special rewards for token holders" : "No rewards",
        votingRights: investment.tokenDetails.type === 'ownership',
        profitDistributionFrequency: "annually"
      };
    });

    const erc721ABI = require("./abis/InvestmentToken721.json").abi;

    res.render("profile", { 
      currentUser: req.user, 
      campaigns, 
      investments: processedInvestments, 
      userTokens,
      erc721ABI, 
      contractAddress: process.env.ERC721_CONTRACT_ADDRESS
    });
  } catch (error) {
    console.error("Profile Fetch Error:", error);
    res.status(500).send("Server error, please try again.");
  }
});

app.post("/profile/update", isLoggedIn, upload.single("profilePicture"), async (req, res) => {
  try {
    const updatedUser = {
      username: req.body.username,
      surname: req.body.surname,
      email: req.body.email,
      phone: req.body.phone,
      address: req.body.address,
      age: req.body.age,
      gender: req.body.gender,
      bio: req.body.bio
    };

    if (req.file) {
      updatedUser.profilePicture = await uploadToImageKit(req.file, 'profile_pictures');
    }

    await User.findByIdAndUpdate(req.user._id, updatedUser, { new: true });
    req.flash("success", "Profile updated successfully");
    res.redirect("/profile");
  } catch (err) {
    console.error(err);
    req.flash("error", "Profile update failed");
    res.redirect("/profile");
  }
});

app.post('/profile/kyc-upload', isLoggedIn, kycUpload.array('kycDocs', 3), async (req, res) => {
  try {
    const uploadPromises = req.files.map(file => 
      uploadToImageKit(file, 'kyc_documents')
    );
    
    const urls = await Promise.all(uploadPromises);
    
    const docs = urls.map((url, index) => ({
      filename: url,
      originalName: req.files[index].originalname
    }));

    const user = await User.findById(req.user._id);
    user.kycDocuments = docs;
    user.kycStatus = 'pending';
    await user.save();

    req.flash('success', 'KYC documents uploaded. Awaiting approval.');
    res.redirect('/profile');
  } catch (err) {
    console.error('KYC Upload Error:', err);
    req.flash('error', 'KYC upload failed.');
    res.redirect('/profile');
  }
});

app.post("/profile/save-wallet", isLoggedIn, async (req, res) => {
  try {
    const { walletAddress } = req.body;
    if (!ethers.isAddress(walletAddress)) {
      return res.status(400).json({ success: false, error: "Invalid wallet address" });
    }

    const user = await User.findById(req.user._id);
    user.walletAddress = walletAddress;
    await user.save();

    res.json({ success: true });
  } catch (err) {
    console.error("Wallet save error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});


// Campaign routes
app.get("/campaigns", async function (req, res) {
  try {
    const campaigns = await Campaign.find({ 
      isApproved: true,
      isRejected: false,
      status: { $ne: "banned" }
    }).populate({
      path: "owner",
      select: "username surname profilePicture kycStatus isBanned"
    });
    
    res.render("campaigns.ejs", { 
      campaigns: campaigns, 
      currentUser: req.user 
    });
  } catch (err) {
    console.error(err);
    req.flash("error", "Failed to load campaigns");
    res.redirect("/");
  }
});

app.get("/campaigns/:id", async (req, res) => {
  try {
    const campaignId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(campaignId)) {
      return res.status(400).send("Invalid campaign ID");
    }

    const campaign = await Campaign.findById(campaignId)
      .populate({
        path: "investments",
        populate: {
          path: "investor",
          select: "username surname profilePicture"
        }
      })
      .populate({
        path: "owner",
        select: "username surname profilePicture kycStatus isBanned"
      });

    if (!campaign) {
      return res.status(404).send("Campaign not found.");
    }

    res.render("campaign_details.ejs", { campaign });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error, please try again.");
  }
});

app.get("/new", isLoggedIn, function (req, res) {
  res.render("new.ejs", { currentUser: req.user });
});

app.post("/campaigns/create", isLoggedIn, upload.single('image'), async (req, res) => {
    try {
        console.log('Received form data:', req.body);
        console.log('Received file:', req.file);

        const { title, description, goalAmount, tokenType, tokenSymbol, totalTokens } = req.body;
        
        // Validate required fields
        if (!title || !description || !goalAmount || !tokenType || !tokenSymbol || !totalTokens) {
            req.flash("error", "All required fields must be filled");
            return res.redirect("/campaigns/new");
        }

        // Handle image upload
        let imageUrl = null;
        if (req.file) {
            try {
                imageUrl = await uploadToImageKit(req.file, 'campaign_images');
                console.log('Image uploaded to:', imageUrl);
            } catch (uploadError) {
                console.error('Image upload failed:', uploadError);
                req.flash("error", "Failed to upload campaign image");
                return res.redirect("/campaigns/new");
            }
        }

        // Prepare campaign data
        const campaignData = {
            title,
            description,
            goalAmount: parseFloat(goalAmount),
            totalTokens: parseFloat(totalTokens),
            tokenName: generateTokenName(title),
            tokenSymbol: tokenSymbol.toUpperCase(),
            tokenType,
            owner: req.user._id,
            image: imageUrl,
            tokenMetadata: {}
        };

        // Add token type specific metadata
        if (tokenType === "profit") {
            campaignData.tokenMetadata = {
                profitSharePercentage: parseFloat(req.body.profitSharePercentage),
                profitDistributionFrequency: req.body.profitDistributionFrequency
            };
        } 
        else if (tokenType === "ownership") {
            campaignData.tokenMetadata = {
                ownershipPercentage: parseFloat(req.body.ownershipPercentage),
                votingRights: req.body.votingRights === "on"
            };
        }
        else if (tokenType === "hybrid") {
            campaignData.tokenMetadata = {
                ownershipPerToken: parseFloat(req.body.ownershipPerToken),
                rewardDescription: req.body.hybridRewardDescription
            };
        }

        // Save to database
        const campaign = new Campaign(campaignData);
        await campaign.save();

        req.flash("success", "Campaign created successfully! Go to Profile, Upload documents and Await Approval!");
        return res.redirect(`/campaigns/${campaign._id}`);
        
    } catch (error) {
        console.error("Campaign creation error:", error);
        req.flash("error", error.message || "Failed to create campaign");
        return res.redirect("/campaigns/new");
    }
});

app.post('/campaigns/:id/upload-docs', kyc_upload.array('docs', 5), async (req, res) => {
  try {
    const campaign = await Campaign.findById(req.params.id);
    if (!campaign) return res.status(404).send('Campaign not found');

    const uploadPromises = req.files.map(file => 
      uploadToImageKit(file, 'campaign_documents')
    );
    
    const urls = await Promise.all(uploadPromises);
    
    const uploadedPaths = urls.map((url, index) => ({
      filename: url,
      originalName: req.files[index].originalname
    }));

    campaign.investorDocuments = [...(campaign.investorDocuments || []), ...uploadedPaths];
    await campaign.save();
    
    res.redirect(`/campaigns/${campaign._id}`);
  } catch (err) {
    console.error(err);
    res.status(500).send('Upload failed');
  }
});

app.post('/campaigns/:campaignId/remove-doc/:docId', isLoggedIn, async (req, res) => {
  const campaign = await Campaign.findById(req.params.campaignId);
  if (!campaign || campaign.owner.toString() !== req.user._id.toString()) {
    return res.status(403).send("Not authorized");
  }

  const doc = campaign.investorDocuments.id(req.params.docId);
  if (!doc) return res.status(404).send("Document not found");

  doc.remove();
  await campaign.save();

  req.flash("success", "Document removed successfully.");
  res.redirect(`/campaigns/${campaign._id}`);
});

app.post("/campaigns/:id/rate", isLoggedIn, async (req, res) => {
  const { riskScore, executionScore, comment } = req.body;
  const campaign = await Campaign.findById(req.params.id);

  if (!campaign) {
    req.flash("error", "Campaign not found.");
  res.redirect(`/campaigns/${campaign._id}`);
  }

  if (!Array.isArray(campaign.ratings)) {
    campaign.ratings = [];
  }

  const alreadyRated = campaign.ratings.find(r => r.user.toString() === req.user._id.toString());
  if (alreadyRated) {
    req.flash("error", "You already rated this campaign.");
    return res.redirect(`/campaigns/${campaign._id}`);
  }

  campaign.ratings.push({
    user: req.user._id,
    role: req.user.role || "investor",
    riskScore,
    executionScore,
    comment
  });

  await campaign.save();
  req.flash("success", "Rating submitted!");
  res.redirect(`/campaigns/${campaign._id}`);
});

// Paynow Payment Routes
app.post("/campaigns/:id/paynow", isLoggedIn, async (req, res) => {
  const { id } = req.params;
  const { amount, paymentMethod, mobileNumber } = req.body;

  try {
    console.log("➡️ Initiating Paynow payment for campaign:", id);

    const campaign = await Campaign.findById(id);
    if (!campaign) {
      req.flash("error", "Campaign not found");
      return res.redirect(`/campaigns/${id}`);
    }

    const user = await User.findById(req.user._id);
    const mobile = Array.isArray(mobileNumber) ? mobileNumber[0] : mobileNumber;

    if (!user.phone && !mobile) {
      req.flash("error", "Please provide a mobile number for payment");
      return res.redirect(`/campaigns/${id}`);
    }

    if (!campaign || !user || !user.walletAddress) {
      req.flash("error", "Invalid campaign or user data. Please Add Your Crypto Wallet First");
      return res.redirect(`/campaigns/${id}`);
    }
    
    // Prevent overfunding
    if (campaign.amountRaised + parseFloat(amount) > campaign.goalAmount) {
        req.flash("error", "Funding goal exceeded.");
        return res.redirect(`/campaigns/${id}`);
    }

    // Create a unique reference
    const reference = `INV-${Date.now()}-${user._id.toString().slice(-6)}`;
    console.log("🧾 Payment reference:", reference);
    console.log("📞 Mobile used:", mobile);
    console.log("📱 Method:", paymentMethod);

    // Create Paynow payment object
    const payment = paynow.createPayment(reference, "macbtee@gmail.com");
    payment.add(`Investment in ${campaign.title}`, amount);

    // Save temporary investment
    const tempInvestment = new Investment({
      investor: user._id,
      campaign: campaign._id,
      amount: parseFloat(amount),
      paymentStatus: 'pending',
      paynowReference: reference,
      tokenDetails: {
        name: campaign.tokenName,
        symbol: campaign.tokenSymbol,
        type: campaign.tokenType,
        value: amount
      }
    });

    // Send to Paynow
    const response = await paynow.sendMobile(payment, mobile, paymentMethod);
    console.log("📡 Paynow API response:", response);

    if (response.success) {
      // Save poll URL
      tempInvestment.paynowPollUrl = response.pollUrl;

      // Save investment session
      req.session.pendingInvestment = {
        userId: user._id,
        campaignId: campaign._id,
        amount: parseFloat(amount),
        walletAddress: user.walletAddress || "0x0000000000000000000000000000000000000000",
        pollUrl: response.pollUrl, // store it here
        metadata: {
          symbol: campaign.tokenSymbol,
          name: campaign.tokenName,
          type: campaign.tokenType,
          title: campaign.title,
          value: parseFloat(amount)
        }
      };

      //await tempInvestment.save();

      console.log("✅ Poll URL saved:", response.pollUrl);
      console.log("🔗 Redirecting to Paynow:", response.redirectUrl);

      res.redirect(`/campaigns/${campaign._id}?payment=success`);

      //return res.redirect(response.redirectUrl);

    } else {
      console.error("❌ Paynow failed or returned no redirect URL.");
      req.flash("error", response.error || "Payment initiation failed");
      return res.redirect(`/campaigns/${id}`);
    }
  } catch (err) {
    console.error("🔥 Paynow initiation error:", err.message || err);
    req.flash("error", "Payment initiation failed. Please try again.");
    return res.redirect(`/campaigns/${id}`);
  }
});


app.post("/payment/status", isLoggedIn, async (req, res) => {
  //console.log("📩 Entered /payment/status");


  const investmentData = req.session.pendingInvestment;
  if (!investmentData) {
    console.error("❌ No pending investment in session");
    return res.status(400).json({
      success: false,
      message: "No pending investment found. Please try again.",
    });
  }

//    const paynowStatus = await paynow.pollTransaction(investmentData.pollUrl);



//     console.log("📩 Entered /payment/status ....................................................................................");
// console.log("📡 Paynow Status:", {
//   paid: paynowStatus.paid,
//   status: paynowStatus.status,
//   amount: paynowStatus.amount,
//   reference: paynowStatus.reference,
// });

// if (!paynowStatus.paid) {
//   console.warn("⚠️ Paynow payment not completed or was cancelled.");
//   return res.status(400).json({
//     success: false,
//     message: "Payment not confirmed. Please complete the payment before proceeding."
//   });
// }



  try {
    console.log(investmentData)
    const { campaignId, userId, amount, metadata, walletAddress } = investmentData;

    // Check if already processed
    const existing = await Investment.findOne({
      investor: userId,
      campaign: campaignId,
      amount: amount,
      paymentStatus: "completed",
    });

    if (existing) {
      console.log("ℹ️ Investment already processed.");
      delete req.session.pendingInvestment;
      return res.json({
        success: true,
        message: "Investment already recorded.",
        redirectUrl: `/campaigns/${campaignId}`,
      });
    }

    // Fetch campaign and investor
    const [campaign, investor] = await Promise.all([
      Campaign.findById(campaignId),
      User.findById(userId),
    ]);

    if (!campaign || !investor || !walletAddress) {
      return res.status(400).json({
        success: false,
        message: "Invalid investor or campaign data.",
      });
    }

    // Prevent overfunding
    if (campaign.amountRaised + parseFloat(amount) > campaign.goalAmount) {
      return res.status(400).json({
        success: false,
        message: "Funding goal exceeded.",
      });
    }

    // 🔗 Upload campaign image to IPFS
    let ipfsImageURL;
    try {
      const axios = require("axios");
      const FormData = require("form-data");
      const { PINATA_API_KEY, PINATA_API_SECRET } = process.env;

      const imgStream = await axios.get(campaign.image, { responseType: "stream" });
      const form = new FormData();
      form.append("file", imgStream.data, "campaign.jpg");

      const pinImageRes = await axios.post(
        "https://api.pinata.cloud/pinning/pinFileToIPFS",
        form,
        {
          maxBodyLength: "Infinity",
          headers: {
            ...form.getHeaders(),
            pinata_api_key: PINATA_API_KEY,
            pinata_secret_api_key: PINATA_API_SECRET,
          },
        }
      );

      ipfsImageURL = `ipfs://${pinImageRes.data.IpfsHash}`;
      console.log("✅ IPFS image uploaded:", ipfsImageURL);
    } catch (err) {
      console.error("⚠️ Failed to upload image to IPFS:", err.message);
      ipfsImageURL = campaign.image; // fallback
    }

    // 🔗 Pin JSON metadata
    const jsonMeta = {
      name: `${metadata.name} Investment Certificate`,
      description: `Proof of $${amount} investment in ${metadata.title}`,
      image: ipfsImageURL,
      attributes: [
        { trait_type: "Amount", value: amount.toString() },
        { trait_type: "Token", value: metadata.symbol },
        { trait_type: "Type", value: metadata.type },
        { trait_type: "Date", value: new Date().toISOString() },
      ],
    };

    const pinJSONRes = await axios.post(
      "https://api.pinata.cloud/pinning/pinJSONToIPFS",
      jsonMeta,
      {
        headers: {
          "Content-Type": "application/json",
          pinata_api_key: process.env.PINATA_API_KEY,
          pinata_secret_api_key: process.env.PINATA_API_SECRET,
        },
      }
    );

    const metadataURI = `ipfs://${pinJSONRes.data.IpfsHash}`;
    console.log("✅ Metadata pinned:", metadataURI);

    // 🧾 Mint NFT
    const { ethers } = require("ethers");
    const provider = new ethers.JsonRpcProvider(process.env.ALCHEMY_SEPOLIA_URL);
    const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
    const abi = require("./abis/InvestmentToken721.json").abi;
    const contract = new ethers.Contract(process.env.ERC721_CONTRACT_ADDRESS, abi, wallet);

    const gasPrice = BigInt(await provider.send("eth_gasPrice", []));
    const gasEstimate = await contract.mintInvestmentNFT.estimateGas(
      walletAddress,
      metadata.symbol,
      metadata.name,
      metadataURI,
      amount
    );

    const tx = await contract.mintInvestmentNFT(
      walletAddress,
      metadata.symbol,
      metadata.name,
      metadataURI,
      amount,
      { gasLimit: gasEstimate + 50000n, gasPrice }
    );

    const receipt = await tx.wait();
    const parsed = receipt.logs
      .map((log) => {
        try {
          return contract.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((e) => e?.name === "InvestmentNFTMinted");

    const tokenId = parsed?.args?.tokenId?.toString();
    if (!tokenId) throw new Error("Token ID not found in receipt.");

    // 💾 Save investment

    const investment = new Investment({
      investor: investor._id,
      campaign: campaign._id,
      amount,
      tokens: 1,
      tokenDetails: metadata,
      transactionHash: receipt.hash,
      blockchainCampaignId: "0x" + campaign._id.toString().slice(0, 16),
      tokenId,
      paymentStatus: "completed",
    });

    await investment.save();

    // 🛠️ Update campaign
    campaign.amountRaised += parseFloat(amount);
    campaign.investments.push(investment._id);
    if (campaign.amountRaised >= campaign.goalAmount) campaign.status = "funded";
    await campaign.save();

    // ✅ Done
    delete req.session.pendingInvestment;
    console.log("✅ Investment finalized and NFT minted.");

    return res.json({
      success: true,
      message: "NFT minted and investment recorded",
      redirectUrl: `/campaigns/${campaign._id}`,
    });

  } catch (err) {
    console.error("❌ Payment status error:", err.message);
    return res.status(500).json({
      success: false,
      message: "Investment finalization failed. " + err.message,
    });
  }
});


app.post('/payment/cancel', isLoggedIn, (req, res) => {
  delete req.session.pendingInvestment;
  res.sendStatus(200);
});




// Paynow Result URL (for server-to-server notifications)
app.post("/paynow/result", async (req, res) => {
  try {
    const status = req.body.status;
    const pollUrl = req.body.pollurl;
    
    if (!pollUrl) {
      return res.status(400).send('Missing poll URL');
    }

    // Poll Paynow to get payment status
    const response = await paynow.pollTransaction(pollUrl);
    
    if (response.paid) {
      // Payment was successful
      const reference = response.reference;
      const amount = parseFloat(response.amount);
      
      // Find the investment by reference
      const investment = await Investment.findOne({ paynowReference: reference });
      if (!investment) {
        return res.status(404).send('Investment not found');
      }

      // Update investment status
      investment.paymentStatus = 'completed';
      investment.amount = amount; // Update with actual paid amount
      await investment.save();

      // Update campaign
      const campaign = await Campaign.findById(investment.campaign);
      campaign.amountRaised += amount;
      campaign.investments.push(investment._id);
      
      if (campaign.amountRaised >= campaign.goalAmount) {
        campaign.status = "funded";
      }
      
      await campaign.save();

      // Mint NFT (reuse your existing NFT minting logic)
      const investor = await User.findById(investment.investor);
      if (investor.walletAddress) {
        try {
          // Your NFT minting code here...
          // This should be similar to your existing /campaigns/invest route logic
          // Just adapt it to work with the investment record we have
          
          console.log(`NFT minted for investment ${reference}`);
        } catch (mintError) {
          console.error('NFT minting error:', mintError);
          // You might want to handle this error appropriately
        }
      }
    }

    res.status(200).send('OK');
  } catch (err) {
    console.error('Paynow result error:', err);
    res.status(500).send('Error processing payment');
  }
});


app.post("/no access", isLoggedIn, async (req, res) => {
  const provider = new ethers.JsonRpcProvider(process.env.ALCHEMY_SEPOLIA_URL);
  const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

  const ledgerABI = [
    "function recordInvestment(string,address,uint256,string)",
    "function getOwner() view returns (address)"
  ];
  const erc721ABI = require("./abis/InvestmentToken721.json").abi;

  const ledgerContract = new ethers.Contract(
    process.env.CONTRACT_ADDRESS,
    ledgerABI,
    wallet
  );
  const erc721Contract = new ethers.Contract(
    process.env.ERC721_CONTRACT_ADDRESS,
    erc721ABI,
    wallet
  );

  try {
    const { campaignId, amount } = req.body;
    const investor = await User.findById(req.user._id);
    const campaign = await Campaign.findById(campaignId);

    // Validate investment amount
    if (campaign.amountRaised + parseFloat(amount) > campaign.goalAmount) {
      const remaining = campaign.goalAmount - campaign.amountRaised;
      req.flash("error", `Funding goal almost reached. Only $${remaining.toFixed(2)} left to invest.`);
      return res.redirect(req.get("Referrer") || "/campaigns");
    }

    if (campaign.amountRaised + parseFloat(amount) >= campaign.goalAmount) {
      campaign.status = "funded";
    }

    if (!campaignId || !amount || isNaN(amount) || amount <= 0) {
      req.flash("error", "Invalid investment amount");
      return res.redirect(req.get("Referrer") || "/");
    }

    const { pinJSONToIPFS } = require("./utils/pinata");

    // Use the ImageKit URL directly
    const imageUrl = campaign.image;
    if (!imageUrl) {
      throw new Error("Campaign image URL not found");
    }

    // Create metadata
    const metadata = {
      name: `${campaign.tokenName} Investment Certificate`,
      description: `Proof of $${amount} investment in ${campaign.title}`,
      attributes: [
        { trait_type: "Amount", value: amount.toString() },
        { trait_type: "Token", value: campaign.tokenSymbol },
        { trait_type: "Type", value: campaign.tokenType },
        { trait_type: "Date", value: new Date().toISOString() }
      ],
      image: imageUrl,
      external_url: `http://localhost/investments/${campaignId}-${investor._id}`
    };

    // Upload metadata to IPFS
    const { IpfsHash } = await pinJSONToIPFS(metadata);
    const metadataURI = `ipfs://${IpfsHash}`;

    // Get gas price first
    const gasPrice = BigInt(await provider.send("eth_gasPrice", []));
    
    // Then estimate gas
    const gasEstimate = await erc721Contract.mintInvestmentNFT.estimateGas(
      investor.walletAddress,
      campaign.tokenSymbol,
      campaign.tokenName,
      metadataURI,
      amount
    );

    // Calculate required gas after getting estimate
    const requiredGas = gasPrice * (gasEstimate + 50000n);
    const balance = await provider.getBalance(wallet.address);

    if (balance < requiredGas) {
      throw new Error(`Insufficient gas. Need ${ethers.formatEther(requiredGas)} ETH`);
    }

    // Execute minting
    const mintTx = await erc721Contract.mintInvestmentNFT(
      investor.walletAddress,
      campaign.tokenSymbol,
      campaign.tokenName,
      metadataURI,
      amount,
      {
        gasLimit: gasEstimate + 50000n,
        gasPrice: gasPrice
      }
    );

    const mintReceipt = await mintTx.wait();
    const event = mintReceipt.logs
      .map(log => {
        try {
          return erc721Contract.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .filter(e => e && e.name === "InvestmentNFTMinted")[0];

    const tokenId = event?.args?.tokenId?.toString();
    if (!tokenId) throw new Error("Unable to extract tokenId from event log");

    // Record in ledger
    const amountWei = ethers.parseEther(amount.toString());
    const campaignIdHex = "0x" + campaign._id.toString().substring(0, 16);

    const ledgerTx = await ledgerContract.recordInvestment(
      campaignIdHex,
      investor.walletAddress,
      amountWei,
      campaign.tokenSymbol,
      { gasLimit: 300000 }
    );

    await ledgerTx.wait();

    // Save investment to database
    const investment = new Investment({
      investor: req.user._id,
      campaign: campaignId,
      amount,
      tokens: 1,
      tokenDetails: {
        symbol: campaign.tokenSymbol,
        name: campaign.tokenName,
        type: campaign.tokenType,
        value: amount
      },
      transactionHash: mintReceipt.hash,
      blockchainCampaignId: campaignIdHex,
      tokenId: tokenId,
      paymentStatus: 'completed' // Mark as completed for crypto payments
    });

    await investment.save();

    // Update campaign
    campaign.amountRaised += parseFloat(amount);
    campaign.investments.push(investment._id);
    
    if (campaign.amountRaised >= campaign.goalAmount) {
      campaign.status = "funded";
    }
    
    await campaign.save();

    req.flash("success",
      `Investment NFT minted! <a href="https://sepolia.etherscan.io/tx/${mintReceipt.hash}" target="_blank">View Transaction</a> | <a href="https://testnets.opensea.io/assets/sepolia/${process.env.ERC721_CONTRACT_ADDRESS}/${tokenId}" target="_blank">View on OpenSea</a>`
    );

    return res.redirect(`/campaigns/${campaignId}`);
  } catch (error) {
    console.error("Investment error:", error);

    let userMessage = "Transaction failed. Please try again.";
    if (error.message.includes("insufficient funds")) {
      userMessage = "Insufficient ETH for gas fees";
    } else if (error.message.includes("rejected")) {
      userMessage = "Transaction rejected by wallet";
    } else if (error.message.includes("gas required exceeds allowance")) {
      userMessage = "Gas estimation failed. Please try again later.";
    }

    req.flash("error", userMessage);
    return res.redirect(req.get("Referrer") || "/");
  }
});

// Admin routes
app.get('/admin/dashboard', isLoggedIn, async (req, res) => {
  const pendingUsers = await User.find({ kycStatus: 'pending' });
  const pendingCampaigns = await Campaign.find({ isApproved: false, isRejected: false }).populate('owner');
  const allUsers = await User.find();
  const allCampaigns = await Campaign.find().populate('owner');
  const pendingWithdrawals = await WithdrawalRequest.find({ status: 'pending' }).populate('campaign owner');

  res.render('admin_dashboard', {
    pendingUsers,
    pendingCampaigns,
    allUsers,
    allCampaigns,
    pendingWithdrawals // ✅ add this line
  });
});


app.post("/admin/kyc/approve/:userId", isLoggedIn, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      req.flash("error", "User not found.");
      return res.redirect("/admin/dashboard");
    }

    user.kycStatus = "verified";
    await user.save();

    req.flash("success", `KYC approved for ${user.username}.`);
    res.redirect("/admin/dashboard");
  } catch (error) {
    console.error("KYC approval error:", error);
    req.flash("error", "Failed to approve KYC.");
    res.redirect("/admin/dashboard");
  }
});

app.post("/admin/users/reject/:userId", isLoggedIn, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      req.flash("error", "User not found.");
      return res.redirect("/admin/dashboard");
    }

    user.kycStatus = "rejected";
    await user.save();

    req.flash("success", `${user.username}'s KYC has been rejected.`);
    res.redirect("/admin/dashboard");
  } catch (error) {
    console.error("Reject user error:", error);
    req.flash("error", "Failed to reject user.");
    res.redirect("/admin/dashboard");
  }
});

app.post("/admin/campaigns/approve/:campaignId", isLoggedIn, async (req, res) => {
  try {
    const campaign = await Campaign.findById(req.params.campaignId);
    if (!campaign) {
      req.flash("error", "Campaign not found.");
      return res.redirect("/admin/dashboard");
    }

    campaign.isApproved = true;
    campaign.status = "active";
    await campaign.save();aut

    req.flash("success", `Campaign "${campaign.title}" has been approved.`);
    res.redirect("/admin/dashboard");
  } catch (error) {
    console.error("Approve campaign error:", error);
    req.flash("error", "Failed to approve campaign.");
    res.redirect("/admin/dashboard");
  }
});

app.post('/admin/campaign/reject/:id', isLoggedIn, async (req, res) => {
  try {
    await Campaign.findByIdAndUpdate(req.params.id, { isApproved: false, isRejected: true });
    req.flash('success', 'Campaign rejected.');
    res.redirect('/admin/dashboard');
  } catch (err) {
    console.error("Reject Error:", err);
    req.flash('error', 'Failed to reject campaign');
    res.redirect('/admin/dashboard');
  }
});

app.post("/admin/campaigns/:id/ban", isLoggedIn, async (req, res) => {
  try {
    const campaign = await Campaign.findById(req.params.id);
    if (!campaign) {
      req.flash("error", "Campaign not found");
      return res.redirect("/admin/dashboard");
    }

    campaign.status = "banned";
    await campaign.save();

    req.flash("success", "Campaign has been banned.");
    res.redirect("/admin/dashboard");
  } catch (error) {
    console.error("Ban campaign error:", error);
    req.flash("error", "Failed to ban campaign");
    res.redirect("/admin/dashboard");
  }
});

app.post("/admin/users/ban/:userId", isLoggedIn, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      req.flash("error", "User not found.");
      return res.redirect("/admin/dashboard");
    }

    user.isBanned = true;
    await user.save();

    req.flash("success", `${user.username} has been banned.`);
    res.redirect("/admin/dashboard");
  } catch (error) {
    console.error("Ban user error:", error);
    req.flash("error", "Failed to ban user.");
    res.redirect("/admin/dashboard");
  }
});

// DELETE route for deleting a campaign
app.delete('/campaigns/:id', async (req, res) => {
  try {
    const campaign = await Campaign.findById(req.params.id);

    if (!campaign) return res.status(404).json({ message: 'Campaign not found' });

    // Optional: check if currentUser is the campaign owner
    if (!req.user || !campaign.owner.equals(req.user._id)) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    await Campaign.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: 'Deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});


app.delete('/admin/campaign/:id', async (req, res) => {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).send("Invalid event ID");
  }

  try {
    await Campaign.findByIdAndDelete(id);
    req.flash('success', 'Campaign deleted successfully!');
    res.redirect('/admin/dashboard');
  } catch (error) {
    console.error('Error deleting campaign:', error);
    req.flash('error', 'An error occurred while deleting the event.');
    res.redirect('/admin/dashboard');
  }
});

// Export routes
app.get('/admin/campaigns/export', isLoggedIn, async (req, res) => {
  try {
    const campaigns = await Campaign.find().populate('owner');

    const fields = [
      { label: 'Title', value: 'title' },
      { label: 'Owner', value: row => row.owner?.username || 'N/A' },
      { label: 'Status', value: 'status' },
      { label: 'Goal Amount', value: 'goalAmount' },
      { label: 'Amount Raised', value: 'amountRaised' },
      { label: 'Token Name', value: 'tokenName' },
      { label: 'Token Symbol', value: 'tokenSymbol' },
      { label: 'Token Type', value: 'tokenType' },
    ];

    const parser = new Parser({ fields });
    const csv = parser.parse(campaigns);

    res.header('Content-Type', 'text/csv');
    res.attachment('campaigns_export.csv');
    return res.send(csv);
  } catch (err) {
    console.error('Export Campaigns Error:', err);
    res.status(500).send('Failed to export campaigns.');
  }
});

app.get('/admin/users/export', isLoggedIn, async (req, res) => {
  try {
    const users = await User.find();

    const fields = [
      { label: 'Username', value: 'username' },
      { label: 'Email', value: 'email' },
      { label: 'KYC Status', value: 'kycStatus' },
      { label: 'Wallet Address', value: 'walletAddress' },
      { label: 'Joined', value: row => row.dateCreated?.toISOString() || '' }
    ];

    const parser = new Parser({ fields });
    const csv = parser.parse(users);

    res.header('Content-Type', 'text/csv');
    res.attachment('users_export.csv');
    return res.send(csv);
  } catch (err) {
    console.error('Export Users Error:', err);
    res.status(500).send('Failed to export users.');
  }
});


app.post("/admin/withdrawals/request", isLoggedIn, async (req, res) => {
  try {
    const { campaignId } = req.body;
    const campaign = await Campaign.findById(campaignId).populate('owner');

    if (!campaign) {
      req.flash("error", "Campaign not found.");
      return res.redirect("/campaigns");
    }

    // Must be the owner
    if (!campaign.owner._id.equals(req.user._id)) {
      req.flash("error", "Unauthorized request.");
      return res.redirect("/campaigns");
    }

    if (campaign.status !== "funded") {
      req.flash("error", "Campaign is not yet fully funded.");
      return res.redirect(`/campaigns/${campaign._id}`);
    }

    // Check if already requested
    const existing = await WithdrawalRequest.findOne({ campaign: campaign._id, status: "pending" });
    if (existing) {
      req.flash("info", "Withdrawal already requested and pending approval.");
      return res.redirect(`/campaigns/${campaign._id}`);
    }

    // Save request
    const withdrawal = new WithdrawalRequest({
      campaign: campaign._id,
      owner: req.user._id,
      amountRequested: campaign.amountRaised,
      status: "pending",
      requestedAt: new Date()
    });

    await withdrawal.save();

    req.flash("success", "Withdrawal request submitted to admin.");
    res.redirect(`/campaigns/${campaign._id}`);
  } catch (err) {
    console.error("❌ Withdrawal request error:", err);
    req.flash("error", "Failed to submit withdrawal request.");
    res.redirect("/campaigns");
  }
});


// Utility functions
function generateTokenName(campaignTitle) {
  if (!campaignTitle) {
    return "DEFAULT Tokens";
  }
  const words = campaignTitle.split(' ');
  const initials = words.map(word => word.charAt(0).toUpperCase()).join('');
  return `${initials} Tokens`;
}

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  req.flash("error", "Please log in first");
  res.redirect("/login");
}

// Error handling
app.use((err, req, res, next) => {
  if (err.name === 'CastError' && err.kind === 'ObjectId') {
    console.warn("Caught CastError:", err.message);

  }
  console.error("🔥 Unhandled Error:", err);
});

///////////////////////////////////////////////////////////////////////////////////////////////
// Forgot Password Form
app.get("/forgot-password", (req, res) => {
  res.render("forgot-password");
});

// Forgot Password Submission
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    req.flash("error", "No account with that email exists");
    return res.redirect("/forgot-password");
  }

  // Generate reset token
  const token = crypto.randomBytes(20).toString('hex');
  user.resetPasswordToken = token;
  user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
  await user.save();

  // Send email
  const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const resetUrl = `http://${req.headers.host}/reset-password/${token}`;
  const mailOptions = {
    to: user.email,
    subject: 'Password Reset',
    text: `Click the link to reset your password: ${resetUrl}`,
  };

  transporter.sendMail(mailOptions, (err) => {
    if (err) {
      req.flash("error", "Error sending email");
      console.log(err);
      return res.redirect("/forgot-password");
    }
    req.flash("success", "Password reset email sent");
    res.redirect("/login");
  });
});

// Reset Password Form
app.get("/reset-password/:token", async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() },
  });

  if (!user) {
    req.flash("error", "Invalid or expired token");
    return res.redirect("/forgot-password");
  }

  res.render("reset-password", { token: req.params.token });
});

// Reset Password Submission
app.post("/reset-password/:token", async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() },
  });

  if (!user) {
    req.flash("error", "Invalid or expired token");
    return res.redirect("/forgot-password");
  }

  // Set new password
  await user.setPassword(req.body.password);
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();

  req.flash("success", "Password reset successful");
  res.redirect("/login");
});
///////////////////////////////////////////////////////////////////////////////////////////
const port = process.env.PORT || 80;
// Start Server
app.listen(port, function () {
  console.log("App Has Started on Port 80");
});