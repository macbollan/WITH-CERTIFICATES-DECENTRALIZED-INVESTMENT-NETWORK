const express = require("express");
const cloudinary = require("../config/cloudinary");
const upload = require("../config/multer");
const User = require("../models/User.model");
const Event = require("../models/Event.model");

const router = express.Router();

// Upload Profile Picture (User)
router.post("/upload-profile", upload.single("profilePicture"), async (req, res) => {
  try {
    const result = await cloudinary.uploader.upload(req.file.buffer, {
      folder: "matchmaking/profiles",
    });
    const user = await User.findById(req.user.id);
    user.profilePicture = result.secure_url;
    await user.save();
    res.json({ message: "Profile picture uploaded successfully", url: result.secure_url });
  } catch (err) {
    res.status(500).json({ message: "Error uploading image", error: err });
  }
});

// Upload Event Pictures
router.post("/upload-event", upload.array("eventImages", 5), async (req, res) => {
  try {
    const images = [];
    for (const file of req.files) {
      const result = await cloudinary.uploader.upload(file.buffer, {
        folder: "matchmaking/events",
      });
      images.push(result.secure_url);
    }
    const event = await Event.findById(req.body.eventId);
    event.images.push(...images);
    await event.save();
    res.json({ message: "Event images uploaded successfully", images });
  } catch (err) {
    res.status(500).json({ message: "Error uploading event images", error: err });
  }
});

module.exports = router;
