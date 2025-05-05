// scripts/deployToken721.js
const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();

  const Contract = await hre.ethers.getContractFactory("InvestmentToken721");

  // Pass deployer address to match Ownable constructor
  const nft = await Contract.deploy(deployer.address);

  await nft.waitForDeployment();

  console.log("✅ InvestmentToken721 deployed to:", await nft.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
