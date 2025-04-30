// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract InvestmentToken is ERC1155, Ownable {
    using Strings for uint256;

    struct TokenInfo {
        string symbol;
        string name;
        string uri;
        uint256 amount;
    }

    event TokenMinted(
        uint256 indexed tokenId,
        address indexed investor,
        string symbol,
        string name,
        uint256 amount
    );

    mapping(uint256 => TokenInfo) public tokenInfo;

    constructor(string memory initialURI) ERC1155(initialURI) Ownable(msg.sender) {}

    // Main minting function (must be defined BEFORE any functions that call it)
    function mintInvestmentToken(
        address investor,
        uint256 tokenId,
        string memory symbol,
        string memory name,
        string memory metadataURI,
        uint256 amount
    ) public onlyOwner {
        require(investor != address(0), "Invalid address");
        require(amount > 0, "Amount must be positive");
        require(bytes(metadataURI).length > 0, "Empty metadata URI");

        _mint(investor, tokenId, amount, "");
        
        tokenInfo[tokenId] = TokenInfo(symbol, name, metadataURI, amount);
        
        emit TokenMinted(tokenId, investor, symbol, name, amount);
        emit URI(metadataURI, tokenId);
    }

    // Batch minting (now correctly placed AFTER mintInvestmentToken)
    function mintBatchInvestmentToken(
        address[] calldata investors,
        uint256[] calldata tokenIds,
        string[] calldata symbols,
        string[] calldata names,
        string[] calldata metadataURIs,
        uint256[] calldata amounts
    ) external onlyOwner {
        require(
            investors.length == tokenIds.length &&
            tokenIds.length == symbols.length &&
            symbols.length == names.length &&
            names.length == metadataURIs.length &&
            metadataURIs.length == amounts.length,
            "Array length mismatch"
        );

        for (uint256 i = 0; i < tokenIds.length; i++) {
            mintInvestmentToken(
                investors[i],
                tokenIds[i],
                symbols[i],
                names[i],
                metadataURIs[i],
                amounts[i]
            );
        }
    }

    function uri(uint256 tokenId) public view override returns (string memory) {
        require(bytes(tokenInfo[tokenId].uri).length > 0, "Token does not exist");
        return tokenInfo[tokenId].uri;
    }

    function updateTokenURI(uint256 tokenId, string memory newURI) external onlyOwner {
        require(bytes(tokenInfo[tokenId].uri).length > 0, "Token not minted");
        tokenInfo[tokenId].uri = newURI;
        emit URI(newURI, tokenId);
    }
}
