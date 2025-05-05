const FormData = require("form-data");
const fs = require("fs");
const axios = require("axios");
const path = require("path");
require('dotenv').config();


// Upload JSON metadata
async function pinJSONToIPFS(json) {
  const url = `https://api.pinata.cloud/pinning/pinJSONToIPFS`;

  const res = await axios.post(url, json, {
    headers: {
      pinata_api_key: process.env.PINATA_API_KEY,
      pinata_secret_api_key: process.env.PINATA_API_SECRET
    }
  });

  return res.data; // { IpfsHash: "..." }
}

// Upload image file
async function pinFileToIPFS(filePath) {
  const data = new FormData();
  data.append("file", fs.createReadStream(filePath));

  const res = await axios.post(
    "https://api.pinata.cloud/pinning/pinFileToIPFS",
    data,
    {
      maxBodyLength: "Infinity",
      headers: {
        ...data.getHeaders(),
        pinata_api_key: process.env.PINATA_API_KEY,
        pinata_secret_api_key: process.env.PINATA_API_SECRET
      }
    }
  );

  return res.data; // { IpfsHash: "..." }
}

module.exports = {
  pinJSONToIPFS,
  pinFileToIPFS
};
