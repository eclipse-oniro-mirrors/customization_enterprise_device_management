/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "disallowed_wifi_list_plugin.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string SSID_3 = "wifi_name1";
const std::string SSID_4 = "wifi_name2";
const std::string BSSID_3 = "68:77:24:77:A6:D7";
const std::string BSSID_4 = "68:77:24:77:A6:D9";

class DisallowedWifiListPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};
void DisallowedWifiListPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowedWifiListPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicyEmpty
 * @tc.desc: Test DisallowWifiListPlugin::OnSetPolicy function when policy is empty.
 * @tc.type: FUNC
 */
    HWTEST_F(DisallowedWifiListPluginTest, TestOnSetPolicyEmpty, TestSize.Level1)
{
    DisallowWifiListPlugin plugin;
    std::vector<WifiId> policyData;
    std::vector<WifiId> currentData;
    std::vector<WifiId> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyWithDataAndCurrentData
 * @tc.desc: Test DisallowWifiListPlugin::OnSetPolicy function when policy has value and current data is empty.
 * @tc.type: FUNC
 */
    HWTEST_F(DisallowedWifiListPluginTest, TestOnSetPolicyWithDataAndCurrentData, TestSize.Level1)
{
    DisallowWifiListPlugin plugin;
    std::vector<WifiId> policyData;
    WifiId id1;
    id1.SetSsid(SSID_3);
    id1.SetBssid(BSSID_3);
    policyData.emplace_back(id1);
    std::vector<WifiId> currentData;
    WifiId id2;
    id2.SetSsid(SSID_4);
    id2.SetBssid(BSSID_4);
    policyData.emplace_back(id2);
    std::vector<WifiId> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyWithDataWithoutCurrentData
 * @tc.desc: Test DisallowWifiListPlugin::OnSetPolicy function when policy has value and current data.
 * @tc.type: FUNC
 */
    HWTEST_F(DisallowedWifiListPluginTest, TestOnSetPolicyWithDataWithoutCurrentData, TestSize.Level1)
{
    DisallowWifiListPlugin plugin;
    std::vector<WifiId> policyData;
    WifiId id;
    id.SetSsid(SSID_3);
    id.SetBssid(BSSID_3);
    policyData.emplace_back(id);
    std::vector<WifiId> currentData;
    std::vector<WifiId> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyWithLargeData
 * @tc.desc: Test DisallowWifiListPlugin::OnSetPolicy data is too large.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedWifiListPluginTest, TestOnSetPolicyWithDataIsTooLarge, TestSize.Level1)
{
    DisallowWifiListPlugin plugin;
    std::vector<WifiId> policyData;
    for (int i = 0; i < 200; ++i) {
    WifiId id;
    id.SetSsid(std::to_string(i));
    id.SetBssid(BSSID_3);
    policyData.emplace_back(id);
    }
    std::vector<WifiId> currentData;
    std::vector<WifiId> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    WifiId id2;
    id2.SetSsid(SSID_3);
    id2.SetBssid(BSSID_3);
    policyData.emplace_back(id2);
    ErrCode ret2 = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret2 == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnSetPolicyWithErrorSsid
 * @tc.desc: Test DisallowWifiListPlugin::OnSetPolicy ssid length > 32.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedWifiListPluginTest, TestOnSetPolicyWithErrorSsid, TestSize.Level1)
{
    DisallowWifiListPlugin plugin;
    std::vector<WifiId> policyData;
    WifiId id;
    id.SetSsid("131313131231231313123123123123123123123313131312312314214124141");
    id.SetBssid(BSSID_3);
    policyData.emplace_back(id);
    std::vector<WifiId> currentData;
    std::vector<WifiId> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnSetPolicyWithErrorBssid
 * @tc.desc: Test DisallowWifiListPlugin::OnSetPolicy bssid error.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedWifiListPluginTest, TestOnSetPolicyWithErrorBssid, TestSize.Level1)
{
    DisallowWifiListPlugin plugin;
    std::vector<WifiId> policyData;
    WifiId id;
    id.SetSsid(SSID_3);
    id.SetBssid("123");
    policyData.emplace_back(id);
    std::vector<WifiId> currentData;
    std::vector<WifiId> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnRemovePolicyEmpty
 * @tc.desc: Test DisallowWifiListPlugin::OnRemovePolicy function when policy is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedWifiListPluginTest, TestOnRemovePolicyEmpty, TestSize.Level1)
{
    DisallowWifiListPlugin plugin;
    std::vector<WifiId> policyData;
    std::vector<WifiId> currentData;
    std::vector<WifiId> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnRemovePolicyWithDataAndCurrentData
 * @tc.desc: Test DisallowWifiListPlugin::OnRemovePolicy function when policy has value and current data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedWifiListPluginTest, TestOnRemovePolicyWithDataAndCurrentData, TestSize.Level1)
{
    DisallowWifiListPlugin plugin;
    std::vector<WifiId> policyData;
    WifiId id1;
    id1.SetSsid(SSID_3);
    id1.SetBssid(BSSID_3);
    policyData.emplace_back(id1);
    std::vector<WifiId> currentData;
    WifiId id2;
    id2.SetSsid(SSID_4);
    id2.SetBssid(BSSID_4);
    policyData.emplace_back(id2);
    std::vector<WifiId> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnRemovePolicyWithLargeData
 * @tc.desc: Test DisallowWifiListPlugin::OnRemovePolicy data is too large.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedWifiListPluginTest, TestOnRemovePolicyWithDataIsTooLarge, TestSize.Level1)
{
    DisallowWifiListPlugin plugin;
    std::vector<WifiId> policyData;
    for (int i = 0; i < 201; ++i) {
    WifiId id;
    id.SetSsid(std::to_string(i));
    id.SetBssid(BSSID_3);
    policyData.emplace_back(id);
    }
    std::vector<WifiId> currentData;
    std::vector<WifiId> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnRemovePolicyWithErrorSsid
 * @tc.desc: Test DisallowWifiListPlugin::OnRemovePolicy ssid length > 32.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedWifiListPluginTest, TestOnRemovePolicyWithErrorSsid, TestSize.Level1)
{
    DisallowWifiListPlugin plugin;
    std::vector<WifiId> policyData;
    WifiId id;
    id.SetSsid("131313131231231313123123123123123123123313131312312314214124141");
    id.SetBssid(BSSID_3);
    policyData.emplace_back(id);
    std::vector<WifiId> currentData;
    std::vector<WifiId> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnRemovePolicyWithErrorBssid
 * @tc.desc: Test DisallowWifiListPlugin::OnRemovePolicy bssid error.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedWifiListPluginTest, TestOnRemovePolicyWithErrorBssid, TestSize.Level1)
{
    DisallowWifiListPlugin plugin;
    std::vector<WifiId> policyData;
    WifiId id;
    id.SetSsid(SSID_3);
    id.SetBssid("123");
    policyData.emplace_back(id);
    std::vector<WifiId> currentData;
    std::vector<WifiId> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnAdminRemovePolicyEmpty
 * @tc.desc: Test DisallowWifiListPlugin::OnAdminRemove function when policy is true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedWifiListPluginTest, TestOnAdminRemovePolicyEmpty, TestSize.Level1)
{
    DisallowWifiListPlugin plugin;
    std::string adminName{"testAdminName"};
    std::vector<WifiId> policyData;
    std::vector<WifiId> mergeData;
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveFalse
 * @tc.desc: Test DisallowWifiListPlugin::OnAdminRemove function when policy is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedWifiListPluginTest, TestOnAdminRemoveHasPolicy, TestSize.Level1)
{
    DisallowWifiListPlugin plugin;
    std::string adminName{"testAdminName"};
    std::vector<WifiId> policyData;
    WifiId id;
    id.SetSsid(SSID_3);
    id.SetBssid(BSSID_3);
    policyData.emplace_back(id);
    std::vector<WifiId> mergeData;
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
}
}
}