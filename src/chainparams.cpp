// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Genesis";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 25810; // Halving every 25,810 blocks
        consensus.nSubsidyIncreaseHeight = 1055000; // Adjust subsidy to 1 JIN/block at this height
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x00000000d17eef89683ab20776b16edf339b4a327e7fada6b53cc70a70d57884"); // Genesis hash (height 0)
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20;
        consensus.nPowTargetTimespan = 4 * 60 * 60; // 4 hours
        consensus.nPowTargetSpacing = 79;  // 79 sec
        consensus.nAuxpowChainId = 0x00BA; // Auxpow Chain ID = 186
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 23229; // 90% of 25810
        consensus.nMinerConfirmationWindow = 25810; // nSubsidyHalvingInterval, ~23.6 days
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 9999999999; // January 1, 2008 - 1199145601
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 9999999999; // December 31, 2008 - 1230767999

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1519516800; // 02/25/2018 @ 12:00am (UTC)
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1551052800; // 02/25/2019 @ 12:00am (UTC)

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1519516800; // 02/25/2018 @ 12:00am (UTC)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1551052800; // 02/25/2019 @ 12:00am (UTC)

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000104e8bc1b729f2cc26"); // Block 541614

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xd7;
        pchMessageStart[1] = 0xc4;
        pchMessageStart[2] = 0xef;
        pchMessageStart[3] = 0xeb;
        nDefaultPort = 23099;
        nPruneAfterHeight = 100000;

        uint256 hash;
        genesis = CreateGenesisBlock(1471801377, 1923087, 0x1e0ffff0, 1, 1 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        // printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
        // printf("genesis.hashMerkleRoot = %s\n", genesis.hashMerkleRoot.ToString().c_str());
        // printf("genesis.nNonce = %u\n", genesis.nNonce);
        assert(consensus.hashGenesisBlock == uint256S("0x000005195817cd43b068ee6dcd091109e937b4b5c322c6a2b23a93912e19bb76"));
        assert(genesis.hashMerkleRoot == uint256S("0x18c372fe354185169070e1c23188f3d028271d8445e1be02f50db9aa353ed056"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("seed1.jin.exchange", "seed1.jin.exchange"));
        vSeeds.push_back(CDNSSeedData("seed2.jin.exchange", "seed2.jin.exchange"));
        vSeeds.push_back(CDNSSeedData("seed3.jin-coin.info", "seed3.jin-coin.info"));
        vSeeds.push_back(CDNSSeedData("seed1.jin-coin.com", "seed1.jin-coin.com"));
        vSeeds.push_back(CDNSSeedData("seed2.jin-coin.com", "seed2.jin-coin.com"));
        vSeeds.push_back(CDNSSeedData("seed3.jin-coin.com", "seed3.jin-coin.com"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,43);  // J
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,21);  // 9
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,171); // S
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        
        /**
         * What makes a good checkpoint block?
         * + Is surrounded by blocks with reasonable timestamps
         *   (no blocks before with a timestamp after, none after with
         *    timestamp before)
         * + Contains no strange transactions
         */
        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 541614, uint256S("0x00000000000e1d0b79889859452375fee02c377cd61686323d4cf62e161e546e"))
            ( 593853, uint256S("0xe309298123a72c79bceb8e6cfb72603ccbe68888292b1f525688c224c9c3b999")),
            1521430684, // * UNIX timestamp of last checkpoint block
            631405,     // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            1200.0      // * estimated number of transactions per day after checkpoint
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 25810; // Halving every 25,810 blocks
        consensus.nSubsidyIncreaseHeight = 1042110; // Adjust subsidy to 1 JIN/block at this height
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x00000000d17eef89683ab20776b16edf339b4a327e7fada6b53cc70a70d57884"); // Genesis hash (height 0)
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 20;
        consensus.nPowTargetTimespan = 4 * 60 * 60; // 4 hours
        consensus.nPowTargetSpacing = 79;  // 79 sec
        consensus.nAuxpowChainId = 0x00BA; // Auxpow Chain ID = 186
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 23229; // 90% of 25810
        consensus.nMinerConfirmationWindow = 25810; // nSubsidyHalvingInterval, ~23.6 days
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 9999999999; // January 1, 2008 - 1199145601
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 9999999999; // December 31, 2008 - 1230767999

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1519516800; // 02/25/2018 @ 12:00am (UTC)
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1551052800; // 02/25/2019 @ 12:00am (UTC)

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1519516800; // 02/25/2018 @ 12:00am (UTC)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1551052800; // 02/25/2019 @ 12:00am (UTC)

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000104e8bc1b729f2cc26"); // Block 541614

        pchMessageStart[0] = 0xbc;
        pchMessageStart[1] = 0xad;
        pchMessageStart[2] = 0xaf;
        pchMessageStart[3] = 0xc4;
        nDefaultPort = 33099;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1471801377, 1923087, 0x1e0ffff0, 1, 1 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        // printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
        // printf("genesis.hashMerkleRoot = %s\n", genesis.hashMerkleRoot.ToString().c_str());
        // printf("genesis.nNonce = %u\n", genesis.nNonce);
        assert(consensus.hashGenesisBlock == uint256S("0x000005195817cd43b068ee6dcd091109e937b4b5c322c6a2b23a93912e19bb76"));
        assert(genesis.hashMerkleRoot == uint256S("0x18c372fe354185169070e1c23188f3d028271d8445e1be02f50db9aa353ed056"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // vSeeds.push_back(CDNSSeedData("mytestseed.org", "mytestseed.org"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,128); // t
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196); // 2
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,52);  // 8
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 541614, uint256S("0x00000000000e1d0b79889859452375fee02c377cd61686323d4cf62e161e546e")),
            1517061285, // * UNIX timestamp of last checkpoint block
            579071,     // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            1100.0      // * estimated number of transactions per day after checkpoint
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 2581;
        consensus.nSubsidyIncreaseHeight = 3000; // Adjust subsidy to 1 JIN/block at this height
        consensus.nMajorityEnforceBlockUpgrade = 510;
        consensus.nMajorityRejectBlockOutdated = 750;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 30 * 60; // 30 min
        consensus.nPowTargetSpacing = 30;  // 30 sec
        consensus.nAuxpowChainId = 0x1940; // Auxpow Chain ID = 6464
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 45; // 75% for testchains
        consensus.nMinerConfirmationWindow = 60; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0xc5;
        pchMessageStart[1] = 0xc7;
        pchMessageStart[2] = 0xd1;
        pchMessageStart[3] = 0xee;
        nDefaultPort = 43099;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1487000020, 0, 0x207fffff, 1, 1 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        // assert(consensus.hashGenesisBlock == uint256S("0x7d861dfe1447cb5ef5d2621a755a517d42a74980744c9996f805b4a4a3d71e91"));
        // assert(genesis.hashMerkleRoot == uint256S("0x037dae4600eea8850fba5fb5146897f57c6f7e0d512cc3875ca8d8f1104b46ad"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x7d861dfe1447cb5ef5d2621a755a517d42a74980744c9996f805b4a4a3d71e91")),
            0,
            0,
            0
        };
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,45);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,48);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,50);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
 
