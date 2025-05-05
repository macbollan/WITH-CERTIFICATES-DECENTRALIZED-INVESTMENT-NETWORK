// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract InvestmentToken721 is ERC721URIStorage, Ownable {
    uint256 private _tokenIdCounter;

    struct InvestmentMetadata {
        string symbol;
        string name;
        string uri;
        uint256 amountUSD;
        uint256 timestamp;
    }

    mapping(uint256 => InvestmentMetadata) public investments;

    event InvestmentNFTMinted(
        uint256 indexed tokenId,
        address indexed investor,
        string symbol,
        string name,
        uint256 amountUSD,
        string uri
    );

    constructor(address initialOwner)
        ERC721("Investment Certificate", "INVEST")
        Ownable(initialOwner)
    {}

    function mintInvestmentNFT(
        address to,
        string memory symbol,
        string memory name,
        string memory uri,
        uint256 amountUSD
    ) public onlyOwner returns (uint256) {
        _tokenIdCounter += 1;
        uint256 tokenId = _tokenIdCounter;

        _mint(to, tokenId);
        _setTokenURI(tokenId, uri);

        investments[tokenId] = InvestmentMetadata({
            symbol: symbol,
            name: name,
            uri: uri,
            amountUSD: amountUSD,
            timestamp: block.timestamp
        });

        emit InvestmentNFTMinted(tokenId, to, symbol, name, amountUSD, uri);

        return tokenId;
    }

    function verifyOwnership(
        uint256 tokenId,
        address claimedOwner
    ) public view returns (bool) {
        return ownerOf(tokenId) == claimedOwner;
    }
}
