// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/server.h"
#include "rpc/client.h"

#include "base58.h"
#include "netbase.h"

#include "test/test_bitcoin.h"

#include <boost/algorithm/string.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/test/unit_test.hpp>

#include <univalue.h>

using namespace std;

UniValue
createArgs(int nRequired, const char* address1=NULL, const char* address2=NULL)
{
    UniValue result(UniValue::VARR);
    result.push_back(nRequired);
    UniValue addresses(UniValue::VARR);
    if (address1) addresses.push_back(address1);
    if (address2) addresses.push_back(address2);
    result.push_back(addresses);
    return result;
}

UniValue CallRPC(string args)
{
    vector<string> vArgs;
    boost::split(vArgs, args, boost::is_any_of(" \t"));
    string strMethod = vArgs[0];
    vArgs.erase(vArgs.begin());
    UniValue params = RPCConvertValues(strMethod, vArgs);
    BOOST_CHECK(tableRPC[strMethod]);
    rpcfn_type method = tableRPC[strMethod]->actor;
    try {
        UniValue result = (*method)(params, false);
        return result;
    }
    catch (const UniValue& objError) {
        throw runtime_error(find_value(objError, "message").get_str());
    }
}


BOOST_FIXTURE_TEST_SUITE(rpc_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(rpc_rawparams)
{
    // Test raw transaction API argument handling
    UniValue r;

    BOOST_CHECK_THROW(CallRPC("getrawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction not_hex"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction b6570d52b0710da2c65c86426a70023af6f3bf979950e4babbc23022890032d2 not_int"), runtime_error);

    BOOST_CHECK_THROW(CallRPC("createrawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction null null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction not_array"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] []"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction {} {}"), runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [] {}"));
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] {} extra"), runtime_error);

    BOOST_CHECK_THROW(CallRPC("decoderawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction DEADBEEF"), runtime_error);
    string rawtx = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5303ae4308062f503253482f04a6846c5a08fabe6d6d6535756c6967686567723a356739683435383762766839673435393836373435010000000000000070000000300100000d2f6e6f64655374726174756d2f0000000003e2470000000000001976a914f64d7afffcd368860eea16e006721e74f8927e9388ac00000000000000001976a914ecf809f1ec0ba4faa909d5175e405902a21282be88ac00000000000000001976a91424a5a20d707a34323509c256fb9aff2ffa4f724e88ac00000000";
    BOOST_CHECK_NO_THROW(r = CallRPC(string("decoderawtransaction ")+rawtx));
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "size").get_int(), 193);
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "version").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "locktime").get_int(), 0);
    BOOST_CHECK_THROW(r = CallRPC(string("decoderawtransaction ")+rawtx+" extra"), runtime_error);

    BOOST_CHECK_THROW(CallRPC("signrawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("signrawtransaction null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("signrawtransaction ff00"), runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC(string("signrawtransaction ")+rawtx));
    BOOST_CHECK_NO_THROW(CallRPC(string("signrawtransaction ")+rawtx+" null null NONE|ANYONECANPAY"));
    BOOST_CHECK_NO_THROW(CallRPC(string("signrawtransaction ")+rawtx+" [] [] NONE|ANYONECANPAY"));
    BOOST_CHECK_THROW(CallRPC(string("signrawtransaction ")+rawtx+" null null badenum"), runtime_error);

    // Only check failure cases for sendrawtransaction, there's no network to send to...
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction DEADBEEF"), runtime_error);
    BOOST_CHECK_THROW(CallRPC(string("sendrawtransaction ")+rawtx+" extra"), runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_rawsign)
{
    UniValue r;
    // input is a 1-of-2 multisig (so is output):
    string prevout =
      "[{\"txid\":\"c47541e37e091b53aa52449cb6c8466c792a637ea1ab0dedc0bee9a43a7ddf3f\","
      "\"vout\":0,\"scriptPubKey\":\"a914b10c9df5f7edf436c697f02f1efdba4cf399615187\","
      "\"redeemScript\":\"512102ae3188ae191d8d921ce848c700ec1fe7475ea89b9713539ae08a940eda4e1fe121027b34f12221e21f7036e295a8e860bb6ef204a757d7d3fbcbb92e3103c2235c0552ae\"}]";
    r = CallRPC(string("createrawtransaction ")+prevout+" "+
      "{\"37ZwzzWow5hUC4oDojRLhEnNuUscyZCh4V\":0.9}");
    string notsigned = r.get_str();
    string privkey1 = "\"SPajmHo6SAX6fV71mn8ktriQb6TmriBF9ZR1Hr4uGZb59Mr2Zg36\"";
    string privkey2 = "\"SP5p65aYxJz4FogAyCzpAyn7Bo7ekLhdWVsH21z1jyi9wt3RBBLN\"";
    r = CallRPC(string("signrawtransaction ")+notsigned+" "+prevout+" "+"[]");
    BOOST_CHECK(find_value(r.get_obj(), "complete").get_bool() == false);
    r = CallRPC(string("signrawtransaction ")+notsigned+" "+prevout+" "+"["+privkey1+","+privkey2+"]");
    BOOST_CHECK(find_value(r.get_obj(), "complete").get_bool() == true);
}

BOOST_AUTO_TEST_CASE(rpc_createraw_op_return)
{
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"68656c6c6f776f726c64\"}"));

    // Allow more than one data transaction output
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"68656c6c6f776f726c64\",\"data\":\"68656c6c6f776f726c64\"}"));

    // Key not "data" (bad address)
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"somedata\":\"68656c6c6f776f726c64\"}"), runtime_error);

    // Bad hex encoding of data output
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"12345\"}"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"12345g\"}"), runtime_error);

    // Data 81 bytes long
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081\"}"));
}

BOOST_AUTO_TEST_CASE(rpc_format_monetary_values)
{
    BOOST_CHECK(ValueFromAmount(0LL).write() == "0.00000000");
    BOOST_CHECK(ValueFromAmount(1LL).write() == "0.00000001");
    BOOST_CHECK(ValueFromAmount(17622195LL).write() == "0.17622195");
    BOOST_CHECK(ValueFromAmount(50000000LL).write() == "0.50000000");
    BOOST_CHECK(ValueFromAmount(89898989LL).write() == "0.89898989");
    BOOST_CHECK(ValueFromAmount(100000000LL).write() == "1.00000000");
    BOOST_CHECK(ValueFromAmount(2099999999999990LL).write() == "20999999.99999990");
    BOOST_CHECK(ValueFromAmount(2099999999999999LL).write() == "20999999.99999999");

    BOOST_CHECK_EQUAL(ValueFromAmount(0).write(), "0.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount((COIN/10000)*123456789).write(), "12345.67890000");
    BOOST_CHECK_EQUAL(ValueFromAmount(-COIN).write(), "-1.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(-COIN/10).write(), "-0.10000000");

    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100000000).write(), "100000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10000000).write(), "10000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*1000000).write(), "1000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100000).write(), "100000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10000).write(), "10000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*1000).write(), "1000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100).write(), "100.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10).write(), "10.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN).write(), "1.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10).write(), "0.10000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100).write(), "0.01000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/1000).write(), "0.00100000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10000).write(), "0.00010000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100000).write(), "0.00001000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/1000000).write(), "0.00000100");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10000000).write(), "0.00000010");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100000000).write(), "0.00000001");
}

static UniValue ValueFromString(const std::string &str)
{
    UniValue value;
    BOOST_CHECK(value.setNumStr(str));
    return value;
}

BOOST_AUTO_TEST_CASE(rpc_parse_monetary_values)
{
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("-0.00000001")), UniValue);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0")), 0LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000000")), 0LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000001")), 1LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.17622195")), 17622195LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.5")), 50000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.50000000")), 50000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.89898989")), 89898989LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1.00000000")), 100000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("20999999.9999999")), 2099999999999990LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("20999999.99999999")), 2099999999999999LL);

    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1e-8")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.1e-7")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.01e-6")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.0000000000000000000000000000000000000000000000000000000000000000000000000001e+68")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("10000000000000000000000000000000000000000000000000000000000000000e-64")), COIN);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000e64")), COIN);

    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e-9")), UniValue); //should fail
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("0.000000019")), UniValue); //should fail
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000001000000")), 1LL); //should pass, cut trailing 0
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("19e-9")), UniValue); //should fail
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.19e-6")), 19); //should pass, leading 0 is present

    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("92233720368.54775808")), UniValue); //overflow error
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e+11")), UniValue); //overflow error
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e11")), UniValue); //overflow error signless
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("93e+9")), UniValue); //overflow error
}

BOOST_AUTO_TEST_CASE(json_parse_errors)
{
    // Valid
    BOOST_CHECK_EQUAL(ParseNonRFCJSONValue("1.0").get_real(), 1.0);
    // Valid, with leading or trailing whitespace
    BOOST_CHECK_EQUAL(ParseNonRFCJSONValue(" 1.0").get_real(), 1.0);
    BOOST_CHECK_EQUAL(ParseNonRFCJSONValue("1.0 ").get_real(), 1.0);

    BOOST_CHECK_THROW(AmountFromValue(ParseNonRFCJSONValue(".19e-6")), std::runtime_error); //should fail, missing leading 0, therefore invalid JSON
    BOOST_CHECK_EQUAL(AmountFromValue(ParseNonRFCJSONValue("0.00000000000000000000000000000000000001e+30 ")), 1);
    // Invalid, initial garbage
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("[1.0"), std::runtime_error);
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("a1.0"), std::runtime_error);
    // Invalid, trailing garbage
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("1.0sds"), std::runtime_error);
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("1.0]"), std::runtime_error);
    // JIN addresses should fail parsing
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("JMPVWiWj2BFD43MUawsGD3rR9GABNjhDAP"), std::runtime_error);
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNL"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_ban)
{
    BOOST_CHECK_NO_THROW(CallRPC(string("clearbanned")));
    
    UniValue r;
    BOOST_CHECK_NO_THROW(r = CallRPC(string("setban 127.0.0.0 add")));
    BOOST_CHECK_THROW(r = CallRPC(string("setban 127.0.0.0:8334")), runtime_error); //portnumber for setban not allowed
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    UniValue ar = r.get_array();
    UniValue o1 = ar[0].get_obj();
    UniValue adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/32");
    BOOST_CHECK_NO_THROW(CallRPC(string("setban 127.0.0.0 remove")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0);

    BOOST_CHECK_NO_THROW(r = CallRPC(string("setban 127.0.0.0/24 add 1607731200 true")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    UniValue banned_until = find_value(o1, "banned_until");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    BOOST_CHECK_EQUAL(banned_until.get_int64(), 1607731200); // absolute time check

    BOOST_CHECK_NO_THROW(CallRPC(string("clearbanned")));

    BOOST_CHECK_NO_THROW(r = CallRPC(string("setban 127.0.0.0/24 add 200")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    banned_until = find_value(o1, "banned_until");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    int64_t now = GetTime();
    BOOST_CHECK(banned_until.get_int64() > now);
    BOOST_CHECK(banned_until.get_int64()-now <= 200);

    // must throw an exception because 127.0.0.1 is in already banned suubnet range
    BOOST_CHECK_THROW(r = CallRPC(string("setban 127.0.0.1 add")), runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(string("setban 127.0.0.0/24 remove")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0);

    BOOST_CHECK_NO_THROW(r = CallRPC(string("setban 127.0.0.0/255.255.0.0 add")));
    BOOST_CHECK_THROW(r = CallRPC(string("setban 127.0.1.1 add")), runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0);


    BOOST_CHECK_THROW(r = CallRPC(string("setban test add")), runtime_error); //invalid IP

    //IPv6 tests
    BOOST_CHECK_NO_THROW(r = CallRPC(string("setban FE80:0000:0000:0000:0202:B3FF:FE1E:8329 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "fe80::202:b3ff:fe1e:8329/128");

    BOOST_CHECK_NO_THROW(CallRPC(string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("setban 2001:db8::/ffff:fffc:0:0:0:0:0:0 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:db8::/30");

    BOOST_CHECK_NO_THROW(CallRPC(string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("setban 2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128");
}

BOOST_AUTO_TEST_CASE(rpc_convert_values_generatetoaddress)
{
    UniValue result;

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", boost::assign::list_of("101")("mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a")));
    BOOST_CHECK_EQUAL(result[0].get_int(), 101);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a");

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", boost::assign::list_of("101")("mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU")));
    BOOST_CHECK_EQUAL(result[0].get_int(), 101);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU");

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", boost::assign::list_of("1")("mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a")("9")));
    BOOST_CHECK_EQUAL(result[0].get_int(), 1);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a");
    BOOST_CHECK_EQUAL(result[2].get_int(), 9);

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", boost::assign::list_of("1")("mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU")("9")));
    BOOST_CHECK_EQUAL(result[0].get_int(), 1);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU");
    BOOST_CHECK_EQUAL(result[2].get_int(), 9);
}

BOOST_AUTO_TEST_SUITE_END()
