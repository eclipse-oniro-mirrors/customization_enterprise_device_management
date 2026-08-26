/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include <gtest/gtest.h>
 
#define private public
#define protected public
#include "allowed_printer_ip_addresses_plugin.h"
#include "allowed_printer_ip_addresses_for_account_plugin.h"
#include "allowed_printer_ip_addresses_util.h"
#undef protected
#undef private
 
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "utils.h"
 
using namespace testing::ext;
using namespace testing;
 
namespace OHOS {
namespace EDM {
namespace TEST {
class AllowedPrinterIpAddressesPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};
 
void AllowedPrinterIpAddressesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}
 
void AllowedPrinterIpAddressesPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}
 
/**
 * @tc.name: TestSetPrinterIpAddressesEmpty
 * @tc.desc: Test set empty printer IP addresses.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPrinterIpAddressesPluginTest, TestSetPrinterIpAddressesEmpty, TestSize.Level1)
{
    AllowedPrinterIPAddressesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    std::vector<std::string> policyData;
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}
 
/**
 * @tc.name: TestSetPrinterIpAddressesWithValidData
 * @tc.desc: Test set printer IP addresses with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPrinterIpAddressesPluginTest, TestSetPrinterIpAddressesWithValidData, TestSize.Level1)
{
    AllowedPrinterIPAddressesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    std::vector<std::string> policyData = { "192.168.1.1", "10.0.0.1" };
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}
 
/**
 * @tc.name: TestSetPrinterIpAddressesWithIPv6
 * @tc.desc: Test set printer IP addresses with IPv6 data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPrinterIpAddressesPluginTest, TestSetPrinterIpAddressesWithIPv6, TestSize.Level1)
{
    AllowedPrinterIPAddressesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    std::vector<std::string> policyData = { "0000:0000:0000:0000:0000:0000:0000:0001",
        "fe80:0000:0000:0000:0000:0000:0000:0001", "2001:0db8:0000:0000:0000:0000:0000:0001" };
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}
 
/**
 * @tc.name: TestSetPrinterIpAddressesExceedMaxSize
 * @tc.desc: Test set printer IP addresses exceed max size.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPrinterIpAddressesPluginTest, TestSetPrinterIpAddressesExceedMaxSize, TestSize.Level1)
{
    AllowedPrinterIPAddressesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    std::vector<std::string> policyData(EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE + 1);
    for (size_t i = 0; i < policyData.size(); ++i) {
        std::stringstream ss;
        ss << "192.168.1." << i;
        policyData[i] = ss.str();
    }
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
}
 
/**
 * @tc.name: TestRemovePrinterIpAddressesEmpty
 * @tc.desc: Test remove empty printer IP addresses.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPrinterIpAddressesPluginTest, TestRemovePrinterIpAddressesEmpty, TestSize.Level1)
{
    AllowedPrinterIPAddressesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    std::vector<std::string> policyData;
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}
 
/**
 * @tc.name: TestRemovePrinterIpAddressesWithData
 * @tc.desc: Test remove printer IP addresses with existing data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPrinterIpAddressesPluginTest, TestRemovePrinterIpAddressesWithData, TestSize.Level1)
{
    AllowedPrinterIPAddressesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    std::vector<std::string> policyData = { "192.168.1.1" };
    std::vector<std::string> currentData = { "192.168.1.1", "10.0.0.1" };
    std::vector<std::string> mergeData = { "192.168.1.1", "10.0.0.1" };
    ErrCode ret = plugin.OnBasicRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}
 
/**
 * @tc.name: TestRemovePrinterIpAddressesNotExist
 * @tc.desc: Test remove printer IP addresses that not exist.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPrinterIpAddressesPluginTest, TestRemovePrinterIpAddressesNotExist, TestSize.Level1)
{
    AllowedPrinterIPAddressesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    std::vector<std::string> policyData = { "192.168.1.100" };
    std::vector<std::string> currentData = { "192.168.1.1", "10.0.0.1" };
    std::vector<std::string> mergeData = { "192.168.1.1", "10.0.0.1" };
    std::vector<std::string> originalCurrentData = currentData;
    std::vector<std::string> originalMergeData = mergeData;
    ErrCode ret = plugin.OnBasicRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(currentData.size(), originalCurrentData.size());
    ASSERT_EQ(mergeData.size(), originalMergeData.size());
}
 
/**
 * @tc.name: TestSetPrinterIpAddressesForAccountEmpty
 * @tc.desc: Test set printer IP addresses for account with empty data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPrinterIpAddressesPluginTest, TestSetPrinterIpAddressesForAccountEmpty, TestSize.Level1)
{
    AllowedPrinterIPAddressesForAccountPlugin plugin;
    plugin.maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    std::vector<std::string> policyData;
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}
 
/**
 * @tc.name: TestSetPrinterIpAddressesForAccountWithValidData
 * @tc.desc: Test set printer IP addresses for account with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPrinterIpAddressesPluginTest, TestSetPrinterIpAddressesForAccountWithValidData, TestSize.Level1)
{
    AllowedPrinterIPAddressesForAccountPlugin plugin;
    plugin.maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    std::vector<std::string> policyData = { "192.168.2.1", "172.16.0.1" };
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}
 
/**
 * @tc.name: TestRemovePrinterIpAddressesForAccountWithData
 * @tc.desc: Test remove printer IP addresses for account.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPrinterIpAddressesPluginTest, TestRemovePrinterIpAddressesForAccountWithData, TestSize.Level1)
{
    AllowedPrinterIPAddressesForAccountPlugin plugin;
    plugin.maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    std::vector<std::string> policyData = { "192.168.2.1" };
    std::vector<std::string> currentData = { "192.168.2.1", "172.16.0.1" };
    std::vector<std::string> mergeData = { "192.168.2.1", "172.16.0.1" };
    ErrCode ret = plugin.OnBasicRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(currentData.size(), 1);
    ASSERT_EQ(mergeData.size(), 2);
}
 
/**
 * @tc.name: TestSetPrinterIpAddressesMergePolicy
 * @tc.desc: Test set printer IP addresses with merge policy.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPrinterIpAddressesPluginTest, TestSetPrinterIpAddressesMergePolicy, TestSize.Level1)
{
    AllowedPrinterIPAddressesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    std::vector<std::string> policyData = { "192.168.1.1" };
    std::vector<std::string> currentData = { "10.0.0.1" };
    std::vector<std::string> mergeData = { "10.0.0.1" };
    ErrCode ret = plugin.OnBasicSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(currentData.size(), 2);
    ASSERT_EQ(mergeData.size(), 2);
}
 
/**
 * @tc.name: TestRemovePrinterIpAddressesMergePolicy
 * @tc.desc: Test remove printer IP addresses with merge policy.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPrinterIpAddressesPluginTest, TestRemovePrinterIpAddressesMergePolicy, TestSize.Level1)
{
    AllowedPrinterIPAddressesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    std::vector<std::string> policyData = { "10.0.0.1" };
    std::vector<std::string> currentData = { "10.0.0.1", "192.168.1.1" };
    std::vector<std::string> mergeData = { "10.0.0.1", "192.168.1.1" };
    ErrCode ret = plugin.OnBasicRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}
 
/**
 * @tc.name: TestSetPrinterIpAddressesCurrentDataFull
 * @tc.desc: Test set printer IP when currentData is already full.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPrinterIpAddressesPluginTest, TestSetPrinterIpAddressesCurrentDataFull, TestSize.Level1)
{
    AllowedPrinterIPAddressesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE;
    std::vector<std::string> currentData;
    for (size_t i = 0; i < EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE; ++i) {
        std::stringstream ss;
        ss << "10.0." << (i / 256) << "." << (i % 256);
        currentData.push_back(ss.str());
    }
    std::vector<std::string> mergeData = currentData;
    std::vector<std::string> policyData = { "192.168.1.1" };
    ErrCode ret = plugin.OnBasicSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAM_ERROR);
    ASSERT_EQ(currentData.size(), EdmConstants::ALLOWED_PRINTER_IP_ADDRESSES_MAX_SIZE);
}
 
/**
 * @tc.name: TestCheckPolicyConflict_NoConflict
 * @tc.desc: Test CheckPolicyConflict when no conflicting policy exists.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPrinterIpAddressesPluginTest, TestCheckPolicyConflict_NoConflict, TestSize.Level1)
{
    ErrCode ret = AllowedPrinterIpAddressesUtil::CheckPolicyConflict(AllowedPrinterIpAddressesType::DEVICE_TYPE);
    ASSERT_EQ(ret, ERR_OK);
    ret = AllowedPrinterIpAddressesUtil::CheckPolicyConflict(AllowedPrinterIpAddressesType::USER_TYPE);
    ASSERT_EQ(ret, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS