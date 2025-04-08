const { ethers } = require("ethers");
require("dotenv").config();

// Initialize provider and wallet
const provider = new ethers.JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL || "http://localhost:8545");
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY || "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", provider);

// Load contract ABI and address
const contractABI = require("../blockchain/artifacts/contracts/InvestmentToken.sol/InvestmentToken.json").abi;
const contractAddress = process.env.CONTRACT_ADDRESS || "0x5FbDB2315678afecb367f032d93F642f64180aa3";

// Initialize contract
const contract = new ethers.Contract(contractAddress, contractABI, wallet);

/**
 * Converts MongoDB ObjectId to a hex string representation
 */
const idToHexString = (id) => {
  return id.toString().replace('ObjectId("', '').replace('")', '');
};

const saveToBlockchain = async (data) => {
    try {
        console.log("[DEBUG] Original data:", data);

        // Convert IDs to hex strings
        const hexCampaignId = idToHexString(data.campaignId);
        const hexInvestorId = idToHexString(data.investorId);
        const amountInWei = ethers.parseEther(data.amount.toString());
        const investorName = `${data.user.firstName} ${data.user.surname}`.trim();

        console.log("[DEBUG] Converted values:", {
            hexCampaignId,
            hexInvestorId,
            amountInWei: amountInWei.toString(),
            investorName
        });

        const tx = await contract.invest(
            hexCampaignId,
            data.campaignName || "Unnamed Campaign",
            hexInvestorId,
            investorName || "Anonymous Investor",
            amountInWei,
            data.tokens || 0,
            data.tokenName || "TOKEN",
            data.tokenValue || 0,
            data.tokenType || "profit", // New parameter
            { value: amountInWei }
        );

        const receipt = await tx.wait();
        console.log("[SUCCESS] Transaction mined:", {
            hash: tx.hash,
            block: receipt.blockNumber
        });
        
        return tx.hash;
    } catch (err) {
        console.error("[ERROR] Full blockchain error:", {
            message: err.message,
            data: err.data,
            stack: err.stack
        });
        throw new Error(`Blockchain processing failed: ${err.message}`);
    }
};

// Add this new function
const createTokenContract = async (campaignData) => {
    try {
      const factory = await ethers.getContractFactory("InvestmentToken");
      const contract = await factory.deploy();
      await contract.deployed();
      return contract.address;
    } catch (err) {
      throw new Error(`Contract deployment failed: ${err.message}`);
    }
  };

/**
 * Fetches full investment details from a transaction hash.
 * Includes both transaction data and decoded event logs.
 */
const getInvestmentFromTransaction = async (transactionHash) => {
    try {
        // Get basic transaction data
        const tx = await provider.getTransaction(transactionHash);
        if (!tx) throw new Error("Transaction not found");

        // Get receipt (for event logs)
        const receipt = await provider.getTransactionReceipt(transactionHash);
        const eventTopic = contract.interface.getEvent("InvestmentMade").topicHash;
        const investmentEvent = receipt.logs.find(log => log.topics[0] === eventTopic);

        if (!investmentEvent) throw new Error("No InvestmentMade event found");

        // Decode event data
        const decodedEvent = contract.interface.decodeEventLog(
            "InvestmentMade",
            investmentEvent.data,
            investmentEvent.topics
        );

        return {
            // Transaction metadata
            transactionHash: tx.hash,
            from: tx.from,
            to: tx.to,
            value: ethers.formatEther(tx.value),
            gasPrice: ethers.formatUnits(tx.gasPrice, "gwei"),
            gasUsed: receipt.gasUsed.toString(),
            status: receipt.status === 1 ? "Success" : "Failed",
            blockNumber: tx.blockNumber,
            timestamp: new Date(
                (await provider.getBlock(tx.blockNumber)).timestamp * 1000
            ).toISOString(),

            // Investment details (from event)
            campaignId: decodedEvent.campaignId.toString(),
            campaignName: decodedEvent.campaignName,
            investorId: decodedEvent.investorId.toString(),
            investorName: decodedEvent.investorName,
            amount: ethers.formatEther(decodedEvent.amount),
            tokens: decodedEvent.tokens.toString(),
            tokenName: decodedEvent.tokenName,
            tokenValue: ethers.formatEther(decodedEvent.tokenValue),
        };
    } catch (err) {
        throw new Error(`Error fetching investment: ${err.message}`);
    }
};

module.exports = { saveToBlockchain, getInvestmentFromTransaction, createTokenContract };