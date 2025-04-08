module.exports = {
    TOKEN_TYPES: {
      PROFIT: "profit",
      OWNERSHIP: "ownership",
      REWARDS: "rewards",
      HYBRID: "hybrid"
    },
    
    getTokenConfig: (tokenType) => {
      const configs = {
        profit: {
          requiredFields: ["profitSharePercentage"],
          defaults: { profitDistributionFrequency: "quarterly" }
        },
        ownership: {
          requiredFields: ["ownershipPercentage"],
          defaults: { votingRights: false }
        },
        rewards: {
          requiredFields: ["rewardDescription"],
          defaults: {}
        },
        hybrid: {
          requiredFields: ["ownershipPerToken", "rewardDescription"],
          defaults: {}
        }
      };
      return configs[tokenType] || {};
    }
  };