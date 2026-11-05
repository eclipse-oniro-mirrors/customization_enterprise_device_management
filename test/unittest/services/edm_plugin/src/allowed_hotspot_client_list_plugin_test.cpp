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
#include "allowed_hotspot_client_list_plugin.h"
#undef private

#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "iplugin.h"
#include "ipolicy_manager.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

const std::string MAC_ADDRESS_1 = "00:11:22:33:44:55";
const std::string MAC_ADDRESS_2 = "AA:BB:CC:DD:EE:FF";

class AllowedHotspotClientListPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void AllowedHotspotClientListPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void AllowedHotspotClientListPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestOnSetPolicyEmpty
 * @tc.desc: Test AllowedHotspotClientListPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListPluginTest, TestOnSetPolicyEmpty, TestSize.Level1)
{
    AllowedHotspotClientListPlugin plugin;
    std::vector<std::string> policyData;
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnSetPolicyWithData
 * @tc.desc: Test AllowedHotspotClientListPlugin::OnSetPolicy with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListPluginTest, TestOnSetPolicyWithData, TestSize.Level1)
{
    AllowedHotspotClientListPlugin plugin;
    std::vector<std::string> policyData{MAC_ADDRESS_1};
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(currentData.size(), 1u);
    ASSERT_EQ(mergeData.size(), 1u);
    ASSERT_EQ(currentData[0], MAC_ADDRESS_1);
}

/**
 * @tc.name: TestOnSetPolicyWithExistingCurrentData
 * @tc.desc: Test OnSetPolicy with existing currentData, union merge should add new address.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListPluginTest, TestOnSetPolicyWithExistingCurrentData, TestSize.Level1)
{
    AllowedHotspotClientListPlugin plugin;
    std::vector<std::string> policyData{MAC_ADDRESS_2};
    std::vector<std::string> currentData{MAC_ADDRESS_1};
    std::vector<std::string> mergeData{MAC_ADDRESS_1};
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(currentData.size(), 2u);
    ASSERT_EQ(mergeData.size(), 2u);
}

/**
 * @tc.name: TestOnSetPolicyDuplicateData
 * @tc.desc: Test OnSetPolicy when data already exists in currentData, union should deduplicate.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListPluginTest, TestOnSetPolicyDuplicateData, TestSize.Level1)
{
    AllowedHotspotClientListPlugin plugin;
    std::vector<std::string> policyData{MAC_ADDRESS_1};
    std::vector<std::string> currentData{MAC_ADDRESS_1};
    std::vector<std::string> mergeData{MAC_ADDRESS_1};
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(currentData.size(), 1u);
    ASSERT_EQ(mergeData.size(), 1u);
}

/**
 * @tc.name: TestOnSetPolicyOverSize
 * @tc.desc: Test OnSetPolicy when data size exceeds max size limit.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListPluginTest, TestOnSetPolicyOverSize, TestSize.Level1)
{
    AllowedHotspotClientListPlugin plugin;
    std::vector<std::string> policyData;
    for (uint32_t i = 0; i <= EdmConstants::ALLOWED_HOTSPOT_CLIENT_LIST_MAX_SIZE; i++) {
        policyData.emplace_back("00:00:00:00:00:" + std::to_string(i));
    }
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::POLICY_LIST_OVER_SIZE);
}

/**
 * @tc.name: TestOnSetPolicyTotalOverSize
 * @tc.desc: Test OnSetPolicy when data + currentData total exceeds max size limit.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListPluginTest, TestOnSetPolicyTotalOverSize, TestSize.Level1)
{
    AllowedHotspotClientListPlugin plugin;
    std::vector<std::string> policyData;
    std::vector<std::string> currentData;
    uint32_t halfSize = EdmConstants::ALLOWED_HOTSPOT_CLIENT_LIST_MAX_SIZE / 2;
    for (uint32_t i = 0; i < halfSize + 1; i++) {
        policyData.emplace_back("00:00:00:00:00:" + std::to_string(i));
        currentData.emplace_back("AA:00:00:00:00:" + std::to_string(i));
    }
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::POLICY_LIST_OVER_SIZE);
}

/**
 * @tc.name: TestOnRemovePolicyEmpty
 * @tc.desc: Test OnRemovePolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListPluginTest, TestOnRemovePolicyEmpty, TestSize.Level1)
{
    AllowedHotspotClientListPlugin plugin;
    std::vector<std::string> policyData;
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnRemovePolicyWithData
 * @tc.desc: Test OnRemovePolicy removes specified MAC from currentData.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListPluginTest, TestOnRemovePolicyWithData, TestSize.Level1)
{
    AllowedHotspotClientListPlugin plugin;
    std::vector<std::string> policyData{MAC_ADDRESS_1};
    std::vector<std::string> currentData{MAC_ADDRESS_1, MAC_ADDRESS_2};
    std::vector<std::string> mergeData{MAC_ADDRESS_1, MAC_ADDRESS_2};
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(currentData.size(), 1u);
    ASSERT_EQ(currentData[0], MAC_ADDRESS_2);
}

/**
 * @tc.name: TestOnRemovePolicyNonExistent
 * @tc.desc: Test OnRemovePolicy when MAC not in currentData, currentData unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListPluginTest, TestOnRemovePolicyNonExistent, TestSize.Level1)
{
    AllowedHotspotClientListPlugin plugin;
    std::vector<std::string> policyData{MAC_ADDRESS_2};
    std::vector<std::string> currentData{MAC_ADDRESS_1};
    std::vector<std::string> mergeData{MAC_ADDRESS_1};
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(currentData.size(), 1u);
    ASSERT_EQ(currentData[0], MAC_ADDRESS_1);
}

/**
 * @tc.name: TestOnRemovePolicyOverSize
 * @tc.desc: Test OnRemovePolicy when data size exceeds max size limit.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListPluginTest, TestOnRemovePolicyOverSize, TestSize.Level1)
{
    AllowedHotspotClientListPlugin plugin;
    std::vector<std::string> policyData;
    for (uint32_t i = 0; i <= EdmConstants::ALLOWED_HOTSPOT_CLIENT_LIST_MAX_SIZE; i++) {
        policyData.emplace_back("00:00:00:00:00:" + std::to_string(i));
    }
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::POLICY_LIST_OVER_SIZE);
}

/**
 * @tc.name: TestOnAdminRemove
 * @tc.desc: Test OnAdminRemove always returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListPluginTest, TestOnAdminRemove, TestSize.Level1)
{
    AllowedHotspotClientListPlugin plugin;
    std::string adminName{"testAdminName"};
    std::vector<std::string> policyData{MAC_ADDRESS_1};
    std::vector<std::string> mergeData{MAC_ADDRESS_1};
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestInitPlugin
 * @tc.desc: Test InitPlugin sets up attributes correctly.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListPluginTest, TestInitPlugin, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = AllowedHotspotClientListPlugin::GetPlugin();
    ASSERT_NE(plugin, nullptr);
    ASSERT_EQ(plugin->GetPolicyName(), PolicyName::POLICY_ALLOWED_HOTSPOT_CLIENT_LIST);
    ASSERT_EQ(plugin->GetCode(), EdmInterfaceCode::ALLOWED_HOTSPOT_CLIENT_LIST);
    ASSERT_TRUE(plugin->NeedSavePolicy());
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
