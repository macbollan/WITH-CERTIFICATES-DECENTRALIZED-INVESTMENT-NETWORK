const hre = require("hardhat");

async function main() {
  // 1. Get contract factory
  const InvestmentToken = await hre.ethers.getContractFactory("InvestmentToken");
  
  // 2. Prepare constructor arguments
  const baseURI = "http://localhost/metadata/"; // Can be mock URL for testing
  const initialOwner = "0xB81EBE547A4B19EC307F9Fd509720d6c622426B7"; // MUST be your actual wallet address
  
  console.log("Deploying with parameters:");
  console.log("- Base URI:", baseURI);
  console.log("- Initial Owner:", initialOwner);
  
  // 3. Deploy with explicit parameters
  const token = await InvestmentToken.deploy(
    baseURI,       // string memory baseURI
    {              // Deployment overrides
      gasLimit: 5000000 // Increased gas limit for Sepolia
    }
  );

  console.log("\nTransaction sent. Waiting for deployment...");
  await token.waitForDeployment();
  
  console.log("\n✅ Contract deployed to:", await token.getAddress());
  console.log("Tx hash:", token.deploymentTransaction().hash);
  
  // For verification
  console.log("\nTo verify run:");
  console.log(`npx hardhat verify --network sepolia ${await token.getAddress()} "${baseURI}"`);
}

main().catch((error) => {
  console.error("❌ Deployment failed:", error.message);
  process.exit(1);
});