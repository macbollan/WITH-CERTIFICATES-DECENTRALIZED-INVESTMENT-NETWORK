// backend/utils/ipfsUploader.js (Mock Version)

//async function uploadMetadataToIPFS(metadata) {
  //  console.log("Simulating upload of metadata:", metadata);
  
    // You can later replace this with a real IPFS URL
    //return "https://yourdomain.com/static/sample-metadata.json";
 // }
  
  //module.exports = { uploadMetadataToIPFS };
 const pinataSDK = require('@pinata/sdk');
require('dotenv').config();

const pinata = new pinataSDK(
  process.env.PINATA_API_KEY,
  process.env.PINATA_API_SECRET
);

// Upload JSON metadata to IPFS
const uploadMetadata = async (metadata) => {
  try {
    const { IpfsHash } = await pinata.pinJSONToIPFS(metadata);
    return { success: true, cid: IpfsHash };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

module.exports = { uploadMetadata };
  