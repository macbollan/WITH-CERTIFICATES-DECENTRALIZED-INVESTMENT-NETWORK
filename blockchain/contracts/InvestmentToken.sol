// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract InvestmentToken is ERC1155, Ownable {
    using Strings for uint256;

    struct Investment {
        string symbol;
        string name;
        string uri;
        uint256 investmentAmount;  // Renamed from 'amount' for clarity
        address investor;          // Track owner explicitly
        uint256 timestamp;
    }

    event TokenMinted(
        uint256 indexed tokenId,
        address indexed investor,
        string symbol,
        string name,
        uint256 investmentAmount,
        string metadataURI        // Added URI to event
    );

    mapping(uint256 => Investment) public investments;
    mapping(uint256 => bool) private _exists;

    constructor() ERC1155("") Ownable(msg.sender) {}  // Remove initialURI

    function mintInvestmentToken(
        address investor,
        uint256 tokenId,
        string memory symbol,
        string memory name,
        string memory metadataURI,
        uint256 investmentAmount  // Now represents USD amount, not token quantity
    ) public onlyOwner {
        require(investor != address(0), "Invalid address");
        require(investmentAmount > 0, "Amount must be positive");
        require(bytes(metadataURI).length > 0, "Empty metadata URI");
        require(!_exists[tokenId], "Token already minted");

        // Always mint exactly 1 NFT
        _mint(investor, tokenId, 1, "");
        
        investments[tokenId] = Investment({
            symbol: symbol,
            name: name,
            uri: metadataURI,
            investmentAmount: investmentAmount,
            investor: investor,
            timestamp: block.timestamp
        });
        
        _exists[tokenId] = true;
        
        emit TokenMinted(tokenId, investor, symbol, name, investmentAmount, metadataURI);
        emit URI(metadataURI, tokenId);
    }

    // Remove batch minting if unused (or keep as is)

    function uri(uint256 tokenId) public view override returns (string memory) {
        require(_exists[tokenId], "Token does not exist");
        return investments[tokenId].uri;
    }

    // Add investor verification
    function verifyOwnership(
        uint256 tokenId, 
        address allegedOwner
    ) external view returns (bool) {
        return investments[tokenId].investor == allegedOwner;
    }
}