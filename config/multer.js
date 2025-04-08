const multer = require("multer");

// Set storage engine
const storage = multer.memoryStorage();

// Upload filter (only image files)
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith("image/")) {
    cb(null, true);
  } else {
    cb(new Error("Not an image! Please upload an image."), false);
  }
};

const upload = multer({ storage, fileFilter });

module.exports = upload;
