// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"
#include <cmath>

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

unsigned int static CalculateNextWorkRequired_V1(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

unsigned int KimotoGravityWell(const CBlockIndex* pindexLast, const CBlockHeader *pblock, uint64_t TargetBlocksSpacingSeconds, uint64_t PastBlocksMin, uint64_t PastBlocksMax, const Consensus::Params& params)
{
        /* current difficulty formula - kimoto gravity well */
        const CBlockIndex *BlockLastSolved                                         = pindexLast;
        const CBlockIndex *BlockReading                                            = pindexLast;

        uint64_t                              PastBlocksMass                       = 0;
        int64_t                               PastRateActualSeconds                = 0;
        int64_t                               PastRateTargetSeconds                = 0;
        double                                PastRateAdjustmentRatio              = double(1);
        arith_uint256                         PastDifficultyAverage;
        arith_uint256                         PastDifficultyAveragePrev;
        double                                EventHorizonDeviation;
        double                                EventHorizonDeviationFast;
        double                                EventHorizonDeviationSlow;
        const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);

        if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64_t)BlockLastSolved->nHeight < PastBlocksMin) { return bnPowLimit.GetCompact(); }

        for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
                if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
                PastBlocksMass++;

                if (i == 1)        { PastDifficultyAverage.SetCompact(BlockReading->nBits); }
                else             //JIN: workaround were to overcome the overflow issue when changing from CBigNum to arith_uint256
                                    if (arith_uint256().SetCompact(BlockReading->nBits) >= PastDifficultyAveragePrev)
                                    PastDifficultyAverage = ((arith_uint256().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev;
                                    else
                                    PastDifficultyAverage = PastDifficultyAveragePrev - ((PastDifficultyAveragePrev - arith_uint256().SetCompact(BlockReading->nBits)) / i);

                PastDifficultyAveragePrev = PastDifficultyAverage;

                PastRateActualSeconds                        = BlockLastSolved->GetBlockTime() - BlockReading->GetBlockTime();
                PastRateTargetSeconds                        = TargetBlocksSpacingSeconds * PastBlocksMass;
                PastRateAdjustmentRatio                        = double(1);
                if (PastRateActualSeconds < 0) { PastRateActualSeconds = 0; }
                if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
                PastRateAdjustmentRatio                        = double(PastRateTargetSeconds) / double(PastRateActualSeconds);
                }
                EventHorizonDeviation                        = 1 + (0.7084 * pow((double(PastBlocksMass)/double(28.2)), -1.228));
                EventHorizonDeviationFast                = EventHorizonDeviation;
                EventHorizonDeviationSlow                = 1 / EventHorizonDeviation;

                if (PastBlocksMass >= PastBlocksMin) {
                        if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) { assert(BlockReading); break; }
                }
                if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
                BlockReading = BlockReading->pprev;
        }

        arith_uint256 bnNew(PastDifficultyAverage);

        if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
            // LogPrintf("Difficulty Retarget - Kimoto Gravity Well\n");
            bnNew *= PastRateActualSeconds;
            bnNew /= PastRateTargetSeconds;
       }
        if (bnNew > bnPowLimit)
            bnNew = bnPowLimit;

 // debug print (commented out due to spamming logs when the loop above breaks)
 //   printf("Difficulty Retarget - Kimoto Gravity Well\n");
 //   printf("PastRateAdjustmentRatio = %g\n", PastRateAdjustmentRatio);
 //   printf("Before: %08x %s\n", BlockLastSolved->nBits, arith_uint256().SetCompact(BlockLastSolved->nBits).ToString().c_str());
 //   printf("After: %08x %s\n", bnNew.GetCompact(), bnNew.ToString().c_str());


        return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    // arith_uint256 bnNew;
    // bnNew.SetCompact(pindexLast->nBits);
    // static arith_uint256 bnStartDifficulty(~uint256(0) >> 27);
    static const arith_uint256 bnStartDifficulty = UintToArith256(uint256S("0000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    const CBlockIndex *BlockLastSolved                                         = pindexLast;
    // int nHeight = pindexLast->nHeight + 1;
    static const arith_uint256 bnGenesisDifficulty = UintToArith256(uint256S("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    // printf("Block: %i\n", pindexLast->nHeight);
    // printf("Block: %08x %s\n", BlockLastSolved->nBits, arith_uint256().SetCompact(BlockLastSolved->nBits).ToString().c_str());
    if (pindexLast->nHeight == 160)
        // printf("Start Difficulty Block 160 - Without Kimoto Gravity Well\n");
        // printf("Block: %08x %s\n", BlockLastSolved->nBits, arith_uint256().SetCompact(BlockLastSolved->nBits).ToString().c_str());
        // printf("After 27: %08x %s\n", bnStartDifficulty.GetCompact(), bnStartDifficulty.ToString().c_str());
        // printf("Genesis: %08x %s\n", bnGenesisDifficulty.GetCompact(), bnGenesisDifficulty.ToString().c_str());
        return bnStartDifficulty.GetCompact();


        static const int64_t                     BlocksTargetSpacing                          = 79; // 79 seconds
        unsigned int                             TimeDaySeconds                               = 60 * 60 * 24;
        int64_t                                  PastSecondsMin                               = TimeDaySeconds * (79.0/60.0) * 0.1;
        int64_t                                  PastSecondsMax                               = TimeDaySeconds * (79.0/60.0) * 2.8;
        uint64_t                                 PastBlocksMin                                = PastSecondsMin / BlocksTargetSpacing;
        uint64_t                                 PastBlocksMax                                = PastSecondsMax / BlocksTargetSpacing;
        return KimotoGravityWell(pindexLast, pblock, BlocksTargetSpacing, PastBlocksMin, PastBlocksMax, params);
    
}

// TODO LED TMP temporary public interface for passing the build of test/pow_tests.cpp only
// TODO LED TMP this code should be removed and test/pow_test.cpp changed to call
// TODO LED TMP our interface to PoW --> GetNextWorkRequired()
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    return CalculateNextWorkRequired_V1(pindexLast, nFirstBlockTime, params);
}
