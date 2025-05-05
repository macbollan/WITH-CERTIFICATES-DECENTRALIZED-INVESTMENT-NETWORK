async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  const InvestmentToken = await ethers.getContractFactory("InvestmentToken");

  // ❌ REMOVE the URI argument if your constructor takes none
  // const contract = await InvestmentToken.deploy("https://gateway.pinata.cloud/ipfs/Qm...");

  // ✅ CORRECT deployment call:
  const contract = await InvestmentToken.deploy();

  await contract.waitForDeployment();
  console.log("InvestmentToken deployed to:", await contract.getAddress());
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

