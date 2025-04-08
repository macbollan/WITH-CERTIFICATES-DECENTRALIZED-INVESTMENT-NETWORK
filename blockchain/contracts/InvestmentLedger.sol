// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract InvestmentLedger {
    struct Investment {
        string campaignId;
        address investor;
        uint256 amount;
        string tokenSymbol;
    }

    Investment[] public investments;
    address public owner;

    event InvestmentRecorded(
        string indexed campaignId,
        address indexed investor,
        uint256 amount,
        string tokenSymbol
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only contract owner can call");
        _;
    }

    function recordInvestment(
        string memory _campaignId,
        address _investor,
        uint256 _amount,
        string memory _tokenSymbol
    ) external onlyOwner {
        require(bytes(_campaignId).length > 0, "Empty campaign ID");
        require(_investor != address(0), "Invalid investor address");
        require(_amount > 0, "Amount must be positive");
        require(bytes(_tokenSymbol).length > 0, "Empty token symbol");

        investments.push(Investment(
            _campaignId,
            _investor,
            _amount,
            _tokenSymbol
        ));
        
        emit InvestmentRecorded(_campaignId, _investor, _amount, _tokenSymbol);
    }

    function getInvestment(uint256 index) public view returns (
        string memory,
        address,
        uint256,
        string memory
    ) {
        require(index < investments.length, "Invalid index");
        Investment memory i = investments[index];
        return (i.campaignId, i.investor, i.amount, i.tokenSymbol);
    }

    function getOwner() public view returns (address) {
        return owner;
    }
}