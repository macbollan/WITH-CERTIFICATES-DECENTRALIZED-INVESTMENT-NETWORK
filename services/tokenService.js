// services/tokenService.js
const CampaignTokenArtifact = require("../blockchain/abis/CampaignToken.json");
const Web3Service = require("./web3Service");

class TokenService {
    static async deployTokenContract(campaignData) {
        const web3 = Web3Service.getWeb3();
        const account = Web3Service.getAccount();
        
        const contract = new web3.eth.Contract(CampaignTokenArtifact.abi);
        
        const deployment = contract.deploy({
            data: CampaignTokenArtifact.bytecode,
            arguments: [
                campaignData.tokenName,
                campaignData.tokenSymbol,
                campaignData._id.toString(),
                campaignData.tokenType,
                campaignData.totalTokens.toString()
            ]
        });

        const gasEstimate = await deployment.estimateGas({ from: account.address });
        const deployedContract = await deployment.send({
            from: account.address,
            gas: gasEstimate
        });

        return deployedContract.options.address;
    }

    static async mintTokens(contractAddress, recipient, amount) {
        const web3 = Web3Service.getWeb3();
        const account = Web3Service.getAccount();
        
        const contract = new web3.eth.Contract(
            CampaignTokenArtifact.abi,
            contractAddress
        );

        const tx = await contract.methods.mint(
            recipient,
            web3.utils.toWei(amount.toString(), 'ether')
        ).send({ from: account.address });

        return tx.transactionHash;
    }
}

module.exports = TokenService;