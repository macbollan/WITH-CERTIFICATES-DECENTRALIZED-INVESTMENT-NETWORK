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




////////////////////////////////////////////////////////////////////////////////////////

// Blockchain setup
const { ethers } = require("ethers");
require("dotenv").config();

const pinataSDK = require('@pinata/sdk');
//const pinata = new pinataSDK(process.env.PINATA_API_KEY, process.env.PINATA_API_SECRET);

// Validate credentials before initialization
if (!process.env.PINATA_API_KEY || !process.env.PINATA_API_SECRET) {
    throw new Error('Missing Pinata credentials in environment variables');
  }
  
  const pinata = new pinataSDK(
    process.env.PINATA_API_KEY.trim(), 
    process.env.PINATA_API_SECRET.trim()
  );
  
  // Test connection immediately
  (async () => {
    try {
      await pinata.testAuthentication();
      console.log('✅ Pinata authentication successful');
    } catch (err) {
      console.error('❌ Pinata authentication failed:', err.message);
      process.exit(1);
    }
  })();
  
// Initialize provider and wallet
const provider = new ethers.JsonRpcProvider(process.env.ALCHEMY_SEPOLIA_URL);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

// Contract ABI
const contractABI = [
  "function recordInvestment(uint256,address,uint256,string)",
  "function getInvestment(uint256) view returns (uint256,address,uint256,string)",

      // Add these
      "function getOwner() view returns (address)",
      "function isOwner() view returns (bool)"
];

// Initialize contract WITH SIGNER
const contract = new ethers.Contract(
  process.env.CONTRACT_ADDRESS,
  contractABI,
  wallet  // This is crucial - must pass the wallet as signer
);



////////////////////////////////////////////////////////////////////////////////////////

const app = express();

// Import User model
const User = require("./models/User.model");
const Campaign = require("./models/Campaign.model");
const Investment = require("./models/Investment.model");

// MongoDB Connection
mongoose.connect("mongodb://localhost/Investment_Network4", {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB Connected"))
    .catch(err => console.log(err));

// Middleware Setup
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "10mb", parameterLimit: 10000 }));
app.use(methodOverride("_method"));
app.use(express.static(path.join(__dirname, "public"))); // Serves static files from 'public' directory
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

// MULTER CONFIGURATION for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadPath = "public/uploads/";
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const imageFilter = (req, file, cb) => {
    if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/i)) {
        return cb(new Error("Only image files are allowed!"), false);
    }
    cb(null, true);
};

const upload = multer({ storage: storage, fileFilter: imageFilter });

/////////////////////////////////////////////////////////////////
// PDF MULTER....
const kyc_storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, 'public/uploads/campaign_docs');
    },
    filename: (req, file, cb) => {
      cb(null, Date.now() + '-' + file.originalname);
    },
  });


const kyc_fileFilter = (req, file, cb) => {
    const allowed = ['.pdf', '.png', '.jpg', '.jpeg'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only PDF, PNG, JPG, and JPEG files are allowed'));
    }
  };

  const kyc_upload = multer({ 
    storage: kyc_storage,
    fileFilter: kyc_fileFilter 
  });
  

  // Upload route
app.post('/campaigns/:id/upload-docs', kyc_upload.array('docs', 5), async (req, res) => {
    try {
      const campaign = await Campaign.findById(req.params.id);
      if (!campaign) return res.status(404).send('Campaign not found');

      const uploadedPaths = req.files.map(f => ({
        filename: '/uploads/campaign_docs/' + f.filename,
        originalName: f.originalname
      }));
      campaign.investorDocuments = [...(campaign.investorDocuments || []), ...uploadedPaths];
  
      await campaign.save();
      res.redirect(`/campaigns/${campaign._id}`);
    } catch (err) {
      console.error(err);
      res.status(500).send('Upload failed');
    }
  });

/////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////
// USER KYC MULTER....
const kycStorage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, 'public/uploads/kyc_docs');
    },
    filename: (req, file, cb) => {
      cb(null, Date.now() + '-' + file.originalname);
    },
  });


const kycFilter = (req, file, cb) => {
    const allowed = ['.pdf', '.png', '.jpg', '.jpeg'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only PDF, PNG, JPG, and JPEG files are allowed'));
    }
  };

  const kycUpload = multer({ 
    storage: kycStorage,
    fileFilter: kycFilter 
  });

  app.post('/profile/kyc-upload', isLoggedIn, kycUpload.array('kycDocs', 3), async (req, res) => {
    try {
      const docs = req.files.map(file => ({
        filename: '/uploads/kyc_docs/' + file.filename,
        originalName: file.originalname
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
  
  ///////////////////////////////////////////////////////////////////////////////////

  app.post('/campaigns/:campaignId/remove-doc/:docId', isLoggedIn, async (req, res) => {
    const campaign = await Campaign.findById(req.params.campaignId);
    if (!campaign || campaign.owner.toString() !== req.user._id.toString()) {
      return res.status(403).send("Not authorized");
    }
  
    const doc = campaign.investorDocuments.id(req.params.docId);
    if (!doc) return res.status(404).send("Document not found");
  
    const filePath = path.join(__dirname, 'public', doc.filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  
    doc.remove(); // remove from array
    await campaign.save();
  
    req.flash("success", "Document removed successfully.");
    res.redirect(`/campaigns/${campaign._id}`);
  });

  app.post("/campaigns/:id/rate", isLoggedIn, async (req, res) => {
    const { riskScore, executionScore, comment } = req.body;
    const campaign = await Campaign.findById(req.params.id);
  
    // Safeguard if campaign not found or ratings is undefined
    if (!campaign) {
      req.flash("error", "Campaign not found.");
      return res.redirect("/campaigns");
    }
  
    // Ensure ratings is always an array
    if (!Array.isArray(campaign.ratings)) {
      campaign.ratings = [];
    }
  
    // Prevent multiple ratings by same user
    const alreadyRated = campaign.ratings.find(r => r.user.toString() === req.user._id.toString());
    if (alreadyRated) {
      req.flash("error", "You already rated this campaign.");
      return res.redirect(`/campaigns/${campaign._id}`);
    }
  
    // Add rating
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
  
  

  //////////////////////////////////////////////////////////////////////////////////

// Helper function to validate ObjectId
function isValidObjectId(id) {
    return mongoose.Types.ObjectId.isValid(id);
}

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
  

// ROUTES
// Login Route
app.post("/login", passport.authenticate("local", {
    successFlash: "Successfully logged in",
    successRedirect: "/profile",
    failureRedirect: "/login",
    failureFlash: true
}));

// Logout Route
app.get("/logout", (req, res) => {
    req.logout(err => {
        if (err) {
            console.log(err);
        } else {
            req.flash("success", "Successfully logged out");
            res.redirect("/campaigns");
        }
    });
});


// Home Page
app.get("/", (req, res) => {
    res.render("index", { currentUser: req.user });
});

// About Page
app.get("/about", (req, res) => {
    res.render("about");
});

// Register Form
app.get("/register", (req, res) => {
    res.render("register", { currentUser: req.user });
});


// Profile Page
app.get("/profile", isLoggedIn, async (req, res) => {
    try {
        const campaigns = await Campaign.find({ owner: req.user._id }).populate("owner");
        const investments = await Investment.find({ investor: req.user._id })
            .populate({
                path: 'campaign',
                select: 'title _id tokenSymbol', // Only populate these fields
                options: { lean: true }
            });

        // Process investments to ensure safe data access
        const processedInvestments = investments.map(investment => {
            return {
                ...investment.toObject(),
                campaign: investment.campaign || { 
                    title: "Deleted Campaign", 
                    _id: null,
                    tokenSymbol: "N/A"
                },
                tokenDetails: {
                    symbol: investment.campaign?.tokenSymbol || "N/A",
                    value: investment.tokenValue || 0
                }
            };
        });

        // Format token information
        const userTokens = processedInvestments.map(investment => {
            console.log(investment.amount,";;;;;;;",investment.tokenDetails.value,"-----",investment.campaign.title);
            return {
                campaignTitle: investment.campaign.title,
                campaignId: investment.campaign._id,
                tokenName: investment.tokenDetails.name || "N/A",
                tokenType: investment.tokenDetails.type || "profit",
                amount: investment.tokens,
                valuePerToken:investment.tokenDetails.value || 0,
                // Add all other required fields with defaults
                profitSharePercentage: (investment.amount/investment.tokenDetails.value)*100,
                ownershipPercentage: investment.ownershipPercentage || 0,
                rewardDescription: investment.rewardDescription || "No rewards",
                votingRights: investment.votingRights || false,
                profitDistributionFrequency: investment.profitDistributionFrequency || "annually"
            };
        });
        const erc1155ABI = require("./abis/InvestmentToken.json").abi;


        res.render("profile", { 
            currentUser: req.user, 
            campaigns, 
            investments: processedInvestments, 
            userTokens,
            erc1155ABI, 
            contractAddress: process.env.ERC1155_CONTRACT_ADDRESS
        });
    } catch (error) {
        console.error("Profile Fetch Error:", error);
        res.status(500).send("Server error, please try again.");
    }
});

// Login Form
app.get("/login", (req, res) => {
    res.render("login", { currentUser: req.user, message: req.flash("error") });
});

// Campaigns Page
app.get("/campaigns", async function (req, res) {
    try {
        const campaigns = await Campaign.find().populate("owner"); // Fetch full owner details;
        res.render("campaigns.ejs", { campaigns: campaigns, currentUser: req.user });
    } catch (err) {
        console.error(err);
        req.flash("error", "Something went wrong");
        res.redirect("/");
    }
});
  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                        // ADMIN STUFF
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//app.get('/admin/', isLoggedIn, async (req, res) => {
  //  const users = await User.find({ kycStatus: 'pending' });
    //res.render('admin_kyc_reviews', { users });
  //});

  const createCsvWriter = require('csv-writer').createObjectCsvWriter;
  
  app.get('/admin/dashboard', isLoggedIn, async (req, res) => {
    const pendingUsers = await User.find({ kycStatus: 'pending' });
    const pendingCampaigns = await Campaign.find({ isApproved: false }).populate('owner');
    const allUsers = await User.find();
    const allCampaigns = await Campaign.find().populate('owner');
  
    res.render('admin_dashboard', {
      pendingUsers,
      pendingCampaigns,
      allUsers,
      allCampaigns
    });
  });
  

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


  
  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Campaign Details Page
app.get("/campaigns/:id", async (req, res) => {
    try {
        const campaignId = req.params.id;

        // Validate ObjectId
        if (!isValidObjectId(campaignId)) {
            return res.status(400).send("Invalid campaign ID");
        }

// Find the campaign by ID
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
        select: "username surname profilePicture  kycStatus" // Corrected to use a single select statement
    })
    .exec();

        if (!campaign) {
            return res.status(404).send("Campaign not found.");
        }

        // Render the campaign details page
        res.render("campaign_details.ejs", {
            campaign: campaign
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error, please try again.");
    }
});



// Register Route
app.post("/register", upload.single("profilePicture"), async (req, res) => {
    try {
        const profilePicture = req.file ? `/uploads/${req.file.filename}` : null;

        const newUser = new User({
            username: req.body.username,
            surname: req.body.surname,
            email: req.body.email,
            phone: req.body.phone,
            address: req.body.address,
            age: req.body.age,
            gender: req.body.gender,
            bio: req.body.bio,
            profilePicture: profilePicture
        });

        User.register(newUser, req.body.password, function (err, user) {
            if (err) {
                req.flash("error", err.message);
                console.log(err);
                return res.redirect("/login");
            }

            passport.authenticate("local")(req, res, function () {
                req.flash("success", "Successfully registered");
                res.redirect("/login");
            });
        });

    } catch (err) {
        console.error(err);
        req.flash("error", "Something went wrong");
        res.redirect("/register");
    }
});


// Update Profile Route
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

        // If new profile picture uploaded, update it
        if (req.file) {
            updatedUser.profilePicture = `/uploads/${req.file.filename}`;
        }

        await User.findByIdAndUpdate(req.user._id, updatedUser, { new: true });

        req.flash("success", "Profile updated successfully");
        res.redirect("/profile");

    } catch (err) {
        console.error(err);
        req.flash("error", "Something went wrong");
        res.redirect("/profile");
    }
});


// Updated Campaign Creation Route


app.post("/campaigns/create", isLoggedIn, upload.single('image'), async (req, res) => {
    const BlockchainService = require("./services/blockchainService");
    try {
        const { title, description, goalAmount, tokenType, tokenSymbol } = req.body;
        const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

        // Validate input fields
        if (!title || !description || !goalAmount || !tokenType || !tokenSymbol) {
            req.flash("error", "All fields are required.");
            return res.redirect("/campaigns/");
        }

        // Create campaign object
        const campaignData = {
            title,
            description,
            goalAmount,
            tokenName: generateTokenName(title),
            tokenSymbol: tokenSymbol.toUpperCase(),
            tokenType,
            totalTokens: goalAmount, // 1 token = $1 by default
            owner: req.user._id,
            image: imagePath,
            tokenMetadata: {
                ...(tokenType === "profit" && { 
                    profitSharePercentage: req.body.profitSharePercentage,
                    profitDistributionFrequency: req.body.profitDistributionFrequency 
                }),
                ...(tokenType === "ownership" && {
                    ownershipPercentage: req.body.ownershipPercentage,
                    votingRights: req.body.votingRights === "on"
                }),
                ...(tokenType === "rewards" && {
                    rewardDescription: req.body.rewardDescription
                }),
                ...(tokenType === "hybrid" && {
                    ownershipPerToken: req.body.ownershipPerToken,
                    rewardDescription: req.body.hybridRewardDescription
                })
            }
        };

        // Deploy token contract
       // campaignData.tokenContractAddress = await BlockchainService.deployTokenContract(campaignData);
        
        // Save to database
        const campaign = new Campaign(campaignData);
        await campaign.save();

        req.flash("success", "Campaign and token created successfully!");
        res.redirect(`/campaigns/${campaign._id}`);
    } catch (error) {
        console.error("Campaign creation error:", error);
        req.flash("error", error.message);
        res.redirect("/campaigns");
    }
});



const { uploadMetadata } = require("./utils/ipfsUploader"); // Or mock
const erc1155ABI = require("./abis/InvestmentToken.json").abi; // ABI from compilation
app.post("/campaigns/invest", isLoggedIn, async (req, res) => {
    const ledgerABI = [
        "function recordInvestment(string,address,uint256,string)",
        "function getOwner() view returns (address)",
        "event InvestmentEvent(string,address,uint256,string)"
    ];

    const ledgerContract = new ethers.Contract(
        process.env.CONTRACT_ADDRESS,
        ledgerABI,
        wallet
    );

    const erc1155Contract = new ethers.Contract(
        process.env.ERC1155_CONTRACT_ADDRESS,
        erc1155ABI,
        wallet
    );

    try {
        const { campaignId, amount } = req.body;
        const investor = await User.findById(req.user._id);
        const campaign = await Campaign.findById(campaignId);

        if (!campaignId || !amount || isNaN(amount) || amount <= 0) {
            req.flash("error", "Invalid investment amount");
            return res.redirect(req.get("Referrer") || "/");
        }

        const tokens = calculateTokens(campaign, amount);
        const amountWei = ethers.parseEther(amount.toString());
        const campaignIdHex = "0x" + campaign._id.toString().substring(0, 16);

        // Verify contract ownership
        const contractOwner = await ledgerContract.getOwner();
        if (ethers.getAddress(contractOwner) !== ethers.getAddress(wallet.address)) {
            throw new Error("Wallet is not contract owner");
        }

        // Upload metadata
        const metadata = {
            name: `${campaign.tokenName} - Investment`,
            description: `Proof of investment in ${campaign.title}`,
            campaignId: campaign._id.toString(),
            attributes: [
                { trait_type: "Token Type", value: campaign.tokenType },
                { trait_type: "Investment Amount", value: `$${amount}` },
                { trait_type: "Token Symbol", value: campaign.tokenSymbol }
            ],
            image: campaign.image || "https://via.placeholder.com/300",
            external_url: `http://localhost/campaigns/${campaign._id}`
        };

        const { IpfsHash } = await pinata.pinJSONToIPFS(metadata);
        const metadataURI = `ipfs://${IpfsHash}`;


        const tokenId = ethers.toBigInt(
            ethers.keccak256(ethers.toUtf8Bytes(campaign._id.toString()))
          );

        const toWallet = "0xB81EBE547A4B19EC307F9Fd509720d6c622426B7";

        console.log("Minting parameters:", {
            to: investor.walletAddress || toWallet,
            tokenId,
            symbol: campaign.tokenSymbol,
            name: campaign.tokenName,
            uri: metadataURI,
            amount: tokens.toString(),
            contract: process.env.ERC1155_CONTRACT_ADDRESS
        });

        // Mint tokens
        const mintTx = await erc1155Contract.mintInvestmentToken(
            investor.walletAddress || toWallet,
            tokenId,
            campaign.tokenSymbol,
            campaign.tokenName,
            metadataURI,
            tokens,
            {
                gasLimit: 500000
            }
        );

        const mintReceipt = await mintTx.wait();

        // Get hex representation of tokenId (updated for Ethers v6)
        const tokenIdHex = ethers.toBeHex(tokenId);


        // Record investment
        const tx = await ledgerContract.recordInvestment(
            campaignIdHex,
            investor.walletAddress || wallet.address,
            amountWei,
            campaign.tokenSymbol,
            { gasLimit: 300000 }
        );

        const receipt = await tx.wait();

        // Save to database
        const investment = new Investment({
            investor: req.user._id,
            campaign: campaignId,
            amount,
            tokens,
            tokenDetails: {
                symbol: campaign.tokenSymbol,
                name: campaign.tokenName,
                type: campaign.tokenType,
                value: tokens / amount
            },
            transactionHash: receipt.hash,
            blockchainCampaignId: campaignIdHex,
            tokenId: tokenIdHex
        });

        await investment.save();

        // Update campaign and investor
        campaign.amountRaised += parseFloat(amount);
        campaign.investors.push(req.user._id);
        campaign.investments.push(investment._id);
        await campaign.save();

        investor.tokens = (investor.tokens || 0) + parseFloat(tokens);
        await investor.save();

        req.flash("success", 
            `Investment successful! ` +
            `<a href="https://sepolia.etherscan.io/tx/${receipt.hash}" target="_blank">View Ledger Tx</a><br>` +
            `<a href="https://sepolia.etherscan.io/tx/${mintReceipt.hash}" target="_blank">View Mint Tx</a>`
        );
        return res.redirect(`/campaigns/${campaignId}`);

    } catch (error) {
        console.error("Investment error:", {
            message: error.message,
            reason: error.reason,
            stack: error.stack,
            data: error.data
        });

        req.flash("error", 
            error.reason || 
            error.message || 
            "Transaction failed. Please try again."
        );
        return res.redirect(req.get("Referrer") || "/");
    }
});

// Helper function to calculate tokens based on campaign type
function calculateTokens(campaign, amount) {
    switch(campaign.tokenType) {
        case "profit":
            return (amount / campaign.goalAmount) * campaign.totalTokens;
        case "ownership":
            const ownershipValue = campaign.tokenMetadata.ownershipPercentage / 100;
            return (amount * campaign.totalTokens) / (campaign.goalAmount * ownershipValue);
        case "rewards":
        case "hybrid":
        default:
            return amount; // 1:1 by default for other types
    }
}


///////////////////////////////////////////////////
//////////////////////////////////////////////////

// Add to server.js or run separately
//async function migrateCampaigns() {
  //  await Campaign.updateMany(
    //    { tokenType: { $exists: false } },
      //  { $set: { 
        //    tokenType: "profit",
          //  tokenSymbol: "TKN",
            //tokenMetadata: {
              //  profitSharePercentage: 10,
                //profitDistributionFrequency: "quarterly"
            //}
        //}}
    //);
    //console.log("Campaigns migrated successfully");
//}

////////////////////////////////////////////////////////
///////////////////////////////////////////////////



// Route to show a user's profile
app.get("/:id/users", async (req, res) => {
    try {
        const userId = req.params.id;

        // Validate ObjectId
        if (!isValidObjectId(userId)) {
            return res.status(400).send("Invalid user ID");
        }

        // Find the user by ID
        const user = await User.findById(userId).exec();
        if (!user) {
            return res.status(404).send("User not found.");
        }

        // Find campaigns owned by the user
        const campaigns = await Campaign.find({ owner: user._id }).populate("owner").exec();
        
        // Fetch investments made by the user
        const investments = await Investment.find({ investor: user._id }).populate("campaign");

                // Format token information
                const userTokens = investments.map(investment => {
                    const tokenValue = investment.tokenValue ?? 0;  // Ensure tokenValue is defined
                    return {
                        campaignTitle: investment.campaign.title,
                        tokenName: investment.tokenDetails.name || "N/A",
                        tokenType: investment.tokenDetails.type,
                        amount: investment.tokens,
                        valuePerToken: investment.tokenDetails.value,
                    };
                });

        // Attach campaigns to the user object
        user.campaigns = campaigns;

        // Check if the current user is an investor or logged in
        const isInvestor = req.user && req.user.role === "investor"; // Adjust based on your logic
        const isLoggedIn = !!req.user; // Check if the user is logged in

        const erc1155ABI = require("./abis/InvestmentToken.json").abi;

        // Render the show profile page with user and campaign data
        res.render("show_profile.ejs", {
            user: user,
            campaigns: campaigns, // Optional: You can still pass campaigns separately if needed
            isInvestor: isInvestor,
            isLoggedIn: isLoggedIn,
            userTokens,
            erc1155ABI, 
            contractAddress: process.env.ERC1155_CONTRACT_ADDRESS
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error, please try again.");
    }
});



// Update Campaign Route with Image Upload
app.post("/campaigns/:id", isLoggedIn, upload.single('image'), async (req, res) => {
    try {
        const campaignId = req.params.id;
        const { title, description, goalAmount, status } = req.body;

        console.log(campaignId);

        const updateData = {
            title,
            description,
            goalAmount,
            status
        };

        // Add image path if new image was uploaded
        if (req.file) {
            updateData.image = `/uploads/${req.file.filename}`;
        }

        const updatedCampaign = await Campaign.findByIdAndUpdate(campaignId, updateData, { new: true });
        
        req.flash("success", "Campaign updated successfully");
        res.redirect("/campaigns");
    } catch (error) {
        console.error(error);
        req.flash("error", "Failed to update campaign");
        res.redirect("back");
    }

});

app.get("/new", isLoggedIn, function (req, res) {
    res.render("new.ejs", { currentUser: req.user });
});


// Utility function to generate a token name based on campaign title
function generateTokenName(campaignTitle) {
    if (!campaignTitle) {
        return "DEFAULT Tokens"; // Fallback if no title is provided
    }

    // Split the title into words, extract initials and format the token name
    const words = campaignTitle.split(' ');
    const initials = words.map(word => word.charAt(0).toUpperCase()).join('');
    
    return `${initials} Tokens`;
}


// Delete Event Route
app.delete('/campaign/:id', async (req, res) => {
    const { id } = req.params;

    // Validate ObjectId
    if (!isValidObjectId(id)) {
        return res.status(400).send("Invalid event ID");
    }

    try {
        await Campaign.findByIdAndDelete(id);
        req.flash('success', 'Campaign deleted successfully!');
        res.redirect('/campaigns');
    } catch (error) {
        console.error('Error deleting event:', error);
        req.flash('error', 'An error occurred while deleting the event.');
        res.redirect('/campaigns');
    }
});




// Middleware to check authentication
function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    req.flash("error", "Please log in first");
    res.redirect("/login");
}

app.get("/:transHash/blockchain", async (req, res) => {
    const transactionHash = req.params.transHash;
    const blockchainService = require("./services/blockchainService");
    console.log("Transaction Hash:", transactionHash);

    try {
        const investment = await blockchainService.getInvestmentFromTransaction(transactionHash);
        res.render('view_on_blockchain', { investment });
    } catch (error) {
        console.log(error);
        res.status(500).send('Error fetching transaction details');
    }
});

app.get("/certificates/:investmentId", isLoggedIn, async (req, res) => {
    try {
        const investmentId = req.params.investmentId;
        const investment = await Investment.findById(investmentId).populate("campaign");

        if (!investment || investment.investor.toString() !== req.user._id.toString()) {
            return res.status(403).send("Unauthorized or not found");
        }

        await generateCertificatePDF(investment, req.user, investment.campaign, res);
    } catch (error) {
        console.error("Certificate generation error:", error);
        res.status(500).send("Error generating certificate");
    }
});


const PDFDocument = require("pdfkit");
const QRCode = require("qrcode");
const { Readable } = require("stream");

// Certificate Generator
async function generateCertificatePDF(investment, user, campaign, res) {
    const doc = new PDFDocument();
    const chunks = [];
    
    // Stream to buffer
    doc.on("data", chunk => chunks.push(chunk));
    doc.on("end", () => {
        const pdfBuffer = Buffer.concat(chunks);
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", "attachment; filename=investment_certificate.pdf");
        res.send(pdfBuffer);
    });

    doc.fontSize(22).text("Investment Certificate", { align: "center" });
    doc.moveDown();

    doc.fontSize(14).text(`Investor: ${user.username} (${user.walletAddress || "No wallet"})`);
    doc.text(`Campaign: ${campaign.title}`);
    doc.text(`Token: ${investment.tokenDetails.symbol} (${investment.tokenDetails.type})`);
    doc.text(`Amount: ${investment.amount} USD → ${investment.tokens} tokens`);
    doc.text(`Date: ${new Date(investment.timeCreated).toLocaleString()}`);
    doc.moveDown();

    const txURL = `https://sepolia.etherscan.io/tx/${investment.transactionHash}`;
    doc.text("Blockchain Transaction:", { underline: true });
    doc.text(txURL);
    doc.moveDown();

    // Generate QR Code
    const qrDataURL = await QRCode.toDataURL(txURL);
    const qrBuffer = Buffer.from(qrDataURL.split(",")[1], "base64");
    doc.image(qrBuffer, { fit: [120, 120], align: "center" });

    doc.moveDown();
    doc.fontSize(10).text("This certificate confirms your participation in a blockchain-based crowdfunding campaign.", {
        align: "justify"
    });

    doc.end();
}

app.use((err, req, res, next) => {
  if (err.name === 'CastError' && err.kind === 'ObjectId') {
    console.warn("Caught CastError:", err.message);
    return res.status(400).render("error", { 
      title: "Invalid ID Format", 
      message: "The ID provided is invalid. Please check your URL or link."
    });
  }

  console.error("🔥 Unhandled Error:", err);
});


// Start Server
app.listen(80, function () {
    console.log("App Has Started on Port 80");
});