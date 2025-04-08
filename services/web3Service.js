// services/web3Service.js
const Web3 = require("web3");
const HDWalletProvider = require("@truffle/hdwallet-provider");

const provider = new HDWalletProvider(
    process.env.DEPLOYER_MNEMONIC,
    process.env.BLOCKCHAIN_PROVIDER_URL
);

const web3 = new Web3(provider);

module.exports = {
    getWeb3: () => web3,
    getAccount: () => {
        const account = web3.eth.accounts.privateKeyToAccount(
            process.env.DEPLOYER_PRIVATE_KEY
        );
        web3.eth.accounts.wallet.add(account);
        return account;
    }
};