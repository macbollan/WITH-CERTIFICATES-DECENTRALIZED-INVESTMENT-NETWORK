// scripts/deploy.js
const hre = require("hardhat");

async function main() {
  // 1. Get the contract factory
  const InvestmentLedger = await hre.ethers.getContractFactory("InvestmentLedger");
  
  // 2. Deploy the contract
  const ledger = await InvestmentLedger.deploy();
  
  // 3. Wait for deployment to complete
  await ledger.waitForDeployment();
  
  // 4. Get the contract address
  const contractAddress = await ledger.getAddress();
  
  console.log("Contract deployed to:", contractAddress);
}

// Proper error handling
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});