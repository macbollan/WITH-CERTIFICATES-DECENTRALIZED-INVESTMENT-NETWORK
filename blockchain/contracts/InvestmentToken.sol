// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract InvestmentToken is ERC1155, Ownable {
    using Strings for uint256;
    
    // Auto-incrementing token ID
    uint256 private _currentTokenId = 1;
    
    // Token metadata structure
    struct TokenData {
        string campaignId;
        string symbol;
        string name;
        string metadataURI;
        uint256 createdAt;
        address campaignOwner;
    }
    
    // Mappings for efficient data access
    mapping(uint256 => TokenData) public tokenData;
    mapping(string => uint256[]) private _campaignTokens;
    mapping(address => uint256[]) private _investorTokens;
    
    // Events
    event TokenMinted(
        address indexed investor,
        uint256 indexed tokenId,
        string indexed campaignId,
        uint256 amount,
        string metadataURI
    );
    
    event MetadataUpdated(uint256 indexed tokenId, string newURI);
    
    // Constructor with initial base URI
    constructor(string memory baseURI) ERC1155(baseURI) Ownable(msg.sender) {}
    
    /**
     * @dev Mints new investment tokens
     */
    function mintInvestmentToken(
        address investor,
        string memory campaignId,
        string memory symbol,
        string memory name,
        string memory metadataURI,
        uint256 amount
    ) external onlyOwner returns (uint256) {
        require(investor != address(0), "Invalid investor address");
        require(bytes(campaignId).length > 0, "Empty campaign ID");
        require(amount > 0, "Amount must be positive");
        
        uint256 tokenId = _currentTokenId++;
        
        _mint(investor, tokenId, amount, "");
        
        tokenData[tokenId] = TokenData({
            campaignId: campaignId,
            symbol: symbol,
            name: name,
            metadataURI: metadataURI,
            createdAt: block.timestamp,
            campaignOwner: msg.sender
        });
        
        _campaignTokens[campaignId].push(tokenId);
        _investorTokens[investor].push(tokenId);
        
        emit TokenMinted(investor, tokenId, campaignId, amount, metadataURI);
        return tokenId;
    }
    
    /**
     * @dev Updates token metadata URI (only campaign owner)
     */
    function updateTokenURI(
        uint256 tokenId,
        string memory newURI
    ) external {
        require(bytes(newURI).length > 0, "Empty URI");
        require(
            msg.sender == tokenData[tokenId].campaignOwner || msg.sender == owner(),
            "Not authorized"
        );
        tokenData[tokenId].metadataURI = newURI;
        emit MetadataUpdated(tokenId, newURI);
    }
    
    /**
     * @dev Returns all token IDs for a specific campaign
     */
    function getCampaignTokens(string memory campaignId) external view returns (uint256[] memory) {
        return _campaignTokens[campaignId];
    }
    
    /**
     * @dev Returns all token IDs for a specific investor
     */
    function getInvestorTokens(address investor) external view returns (uint256[] memory) {
        return _investorTokens[investor];
    }
    
    /**
     * @dev Overrides default URI for OpenSea compatibility
     */
    function uri(uint256 tokenId) public view override returns (string memory) {
        require(exists(tokenId), "Token does not exist");
        return tokenData[tokenId].metadataURI;
    }
    
    /**
     * @dev Checks if token exists
     */
    function exists(uint256 tokenId) public view returns (bool) {
        return bytes(tokenData[tokenId].campaignId).length > 0;
    }
    
    /**
     * @dev Batch transfer tokens
     */
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) public override {
        super.safeBatchTransferFrom(from, to, ids, amounts, data);
        
        // Update investor token tracking
        for (uint256 i = 0; i < ids.length; i++) {
            _updateInvestorTokens(from, to, ids[i]);
        }
    }
    
    /**
     * @dev Single transfer override
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) public override {
        super.safeTransferFrom(from, to, id, amount, data);
        _updateInvestorTokens(from, to, id);
    }
    
    /**
     * @dev Internal function to update investor token tracking
     */
    function _updateInvestorTokens(address from, address to, uint256 tokenId) private {
        // Remove from sender's list
        uint256[] storage senderTokens = _investorTokens[from];
        for (uint256 i = 0; i < senderTokens.length; i++) {
            if (senderTokens[i] == tokenId) {
                senderTokens[i] = senderTokens[senderTokens.length - 1];
                senderTokens.pop();
                break;
            }
        }
        
        // Add to recipient's list
        _investorTokens[to].push(tokenId);
    }
}