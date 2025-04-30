const hre = require("hardhat");

async function main() {
  // Use IPFS/Arweave URI for production (replace with your actual URI)
  const initialURI = "https://gateway.pinata.cloud/ipfs/QmQ1PKhxtViAwvck6xwhtMdKoC7bmyQ6ZmkzUo8bJgXrgp/";
  
  const InvestmentToken = await hre.ethers.getContractFactory("InvestmentToken");
  const token = await InvestmentToken.deploy(initialURI);

  console.log("Deployed to:", await token.getAddress());
  console.log("Verify with:");
  console.log(`npx hardhat verify --network sepolia ${await token.getAddress()} "${initialURI}"`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
