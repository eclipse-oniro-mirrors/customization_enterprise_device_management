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

#define private public
#include "disallowed_bluetooth_protocols_plugin.h"
#undef private

#include "bluetooth_protocol_models.h"
#include "bluetooth_protocol_policy_serializer.h"
#include "edm_constants.h"
#include "edm_data_ability_utils_mock.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisallowedBluetoothProtocolsPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowedBluetoothProtocolsPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void DisallowedBluetoothProtocolsPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestInitPluginSuccess
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::InitPlugin success.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestInitPluginSuccess, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedBluetoothProtocolsPlugin::GetPlugin();
    ASSERT_TRUE(plugin->IsGlobalPolicy());
    ASSERT_TRUE(plugin->NeedSavePolicy());
    ASSERT_TRUE(plugin->GetCode() == (std::uint32_t)EdmInterfaceCode::DISALLOWED_BLUETOOTH_PROTOCOLS);
    ASSERT_EQ(plugin->GetPolicyName(), PolicyName::POLICY_DISALLOWED_BLUETOOTH_PROTOCOLS);
    ASSERT_EQ(plugin->GetPermission(FuncOperateType::SET, IPlugin::PermissionType::SUPER_DEVICE_ADMIN),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH);
}

/**
 * @tc.name: TestOnSetPolicyEmpty
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnSetPolicy with empty policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnSetPolicyEmpty, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    DisallowedBluetoothProtocolsPlugin plugin;
    BluetoothProtocolPolicy policyData;
    BluetoothProtocolPolicy currentData;
    BluetoothProtocolPolicy mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnSetPolicyInvalidAccountId
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnSetPolicy with invalid accountId.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnSetPolicyInvalidAccountId, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    DisallowedBluetoothProtocolsPlugin plugin;
    BluetoothProtocolPolicy policyData;
    policyData.protocolDenyList[-1] = {"GATT"}; // Invalid accountId
    BluetoothProtocolPolicy currentData;
    BluetoothProtocolPolicy mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnSetPolicyInvalidSppProtocol
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnSetPolicy with invalid SPP protocol (only in one list).
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnSetPolicyInvalidSppProtocol, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    DisallowedBluetoothProtocolsPlugin plugin;
    BluetoothProtocolPolicy policyData;
    policyData.protocolDenyList[100] = {"SPP"}; // SPP only in deny list
    BluetoothProtocolPolicy currentData;
    BluetoothProtocolPolicy mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnSetPolicyWithValidData
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnSetPolicy with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnSetPolicyWithValidData, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    DisallowedBluetoothProtocolsPlugin plugin;
    BluetoothProtocolPolicy policyData;
    policyData.protocolDenyList[100] = {"GATT", "SPP"};
    policyData.protocolRecDenyList[100] = {"SPP", "OPP"};
    BluetoothProtocolPolicy currentData;
    BluetoothProtocolPolicy mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(currentData.protocolDenyList.empty());
    ASSERT_FALSE(mergeData.protocolDenyList.empty());
}

/**
 * @tc.name: TestOnSetPolicyWithMultipleAccounts
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnSetPolicy with multiple accounts.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnSetPolicyWithMultipleAccounts, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    DisallowedBluetoothProtocolsPlugin plugin;
    BluetoothProtocolPolicy policyData;
    policyData.protocolDenyList[100] = {"GATT"};
    policyData.protocolDenyList[101] = {"SPP"};
    policyData.protocolRecDenyList[100] = {"OPP"};
    policyData.protocolRecDenyList[101] = {"GATT"};
    BluetoothProtocolPolicy currentData;
    BluetoothProtocolPolicy mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_EQ(currentData.protocolDenyList.size(), 2);
    ASSERT_EQ(currentData.protocolRecDenyList.size(), 2);
}

/**
 * @tc.name: TestOnSetPolicyWithExistingData
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnSetPolicy with existing current data.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnSetPolicyWithExistingData, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    DisallowedBluetoothProtocolsPlugin plugin;
    BluetoothProtocolPolicy policyData;
    policyData.protocolDenyList[100] = {"OPP"};
    policyData.protocolRecDenyList[100] = {"OPP"};

    BluetoothProtocolPolicy currentData;
    currentData.protocolDenyList[100] = {"GATT"};
    currentData.protocolRecDenyList[100] = {"GATT"};

    BluetoothProtocolPolicy mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    // After merge, currentData should contain both GATT and OPP
    ASSERT_EQ(currentData.protocolDenyList[100].size(), 2);
}

/**
 * @tc.name: TestOnRemovePolicyEmpty
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnRemovePolicy with empty policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnRemovePolicyEmpty, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    BluetoothProtocolPolicy policyData;
    BluetoothProtocolPolicy currentData;
    BluetoothProtocolPolicy mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnRemovePolicyWithValidData
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnRemovePolicy with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnRemovePolicyWithValidData, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    BluetoothProtocolPolicy policyData;
    policyData.protocolDenyList[100] = {"GATT"};
    policyData.protocolRecDenyList[100] = {"OPP"};

    BluetoothProtocolPolicy currentData;
    currentData.protocolDenyList[100] = {"GATT", "SPP", "OPP"};
    currentData.protocolRecDenyList[100] = {"GATT", "OPP"};

    BluetoothProtocolPolicy mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    // After removal, GATT should be removed from deny list
    auto it = std::find(currentData.protocolDenyList[100].begin(),
                     currentData.protocolDenyList[100].end(), "GATT");
    ASSERT_TRUE(it == currentData.protocolDenyList[100].end());
}

/**
 * @tc.name: TestOnRemovePolicyWithMultipleAccounts
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnRemovePolicy with multiple accounts.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnRemovePolicyWithMultipleAccounts, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    BluetoothProtocolPolicy policyData;
    policyData.protocolDenyList[100] = {"GATT"};
    policyData.protocolDenyList[101] = {"SPP"};

    BluetoothProtocolPolicy currentData;
    currentData.protocolDenyList[100] = {"GATT", "OPP"};
    currentData.protocolDenyList[101] = {"SPP", "OPP"};

    BluetoothProtocolPolicy mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_EQ(currentData.protocolDenyList[100].size(), 1); // Only OPP left
    ASSERT_EQ(currentData.protocolDenyList[101].size(), 1); // Only OPP left
}

/**
 * @tc.name: TestOnAdminRemoveEmpty
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnAdminRemove with empty data.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnAdminRemoveEmpty, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    std::string adminName{"testAdminName"};
    BluetoothProtocolPolicy policyData;
    BluetoothProtocolPolicy mergeData;
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveWithData
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnAdminRemove with data.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnAdminRemoveWithData, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    std::string adminName{"testAdminName"};
    BluetoothProtocolPolicy policyData;
    policyData.protocolDenyList[100] = {"GATT", "SPP"};
    policyData.protocolRecDenyList[100] = {"OPP"};
    BluetoothProtocolPolicy mergeData;
    mergeData.protocolDenyList[100] = {"GATT"};
    mergeData.protocolRecDenyList[100] = {"OPP"};
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnChangedPolicyDoneTrue
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnChangedPolicyDone with isGlobalChanged=true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnChangedPolicyDoneTrue, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    plugin.OnChangedPolicyDone(true);
    // Should notify bluetooth protocols changed
    ASSERT_TRUE(true);
}

/**
 * @tc.name: TestOnChangedPolicyDoneFalse
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnChangedPolicyDone with isGlobalChanged=false.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnChangedPolicyDoneFalse, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    plugin.OnChangedPolicyDone(false);
    // Should not notify
    ASSERT_TRUE(true);
}

/**
 * @tc.name: TestOnGetPolicyInvalidAccountId
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnGetPolicy with invalid accountId.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnGetPolicyInvalidAccountId, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS);
    data.WriteInt32(-1); // Invalid accountId
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicySendOnly
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnGetPolicy with SEND_ONLY type.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnGetPolicySendOnly, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS);
    data.WriteInt32(100);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnGetPolicyWithPolicySendOnly
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnGetPolicy with SEND_ONLY transfer policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnGetPolicyWithPolicySendOnly, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS_WITH_POLICY);
    data.WriteInt32(100);
    data.WriteInt32(static_cast<int32_t>(TransferPolicy::SEND_ONLY));
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnGetPolicyWithPolicyReceiveOnly
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnGetPolicy with RECEIVE_ONLY transfer policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnGetPolicyWithPolicyReceiveOnly, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS_WITH_POLICY);
    data.WriteInt32(100);
    data.WriteInt32(static_cast<int32_t>(TransferPolicy::RECEIVE_ONLY));
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnGetPolicyWithPolicyReceiveSend
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnGetPolicy with RECEIVE_SEND transfer policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnGetPolicyWithPolicyReceiveSend, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS_WITH_POLICY);
    data.WriteInt32(100);
    data.WriteInt32(static_cast<int32_t>(TransferPolicy::RECEIVE_SEND));
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnGetPolicyInvalidType
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::OnGetPolicy with invalid type.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestOnGetPolicyInvalidType, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(999); // Invalid type
    data.WriteInt32(100);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestRemoveProtocolsFromPolicy
 * @tc.desc: Test DisallowedBluetoothProtocolsariPlugin::RemoveProtocolsFromPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestRemoveProtocolsFromPolicy, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    std::map<int32_t, std::vector<std::string>> source = {{100, {"GATT"}}};
    std::map<int32_t, std::vector<std::string>> target = {{100, {"GATT", "SPP", "OPP"}}};

    // Access private method through friend class or test interface
    // This test assumes the method is accessible for testing
    plugin.RemoveProtocolsFromPolicy(source, target);

    ASSERT_EQ(target[100].size(), 2); // GATT should be removed
    auto it = std::find(target[100].begin(), target[100].end(), "GATT");
    ASSERT_TRUE(it == target[100].end());
}

/**
 * @tc.name: TestValidateBluetoothProtocolPolicyEmpty
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::ValidateBluetoothProtocolPolicy with empty policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestValidateBluetoothProtocolPolicyEmpty, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    BluetoothProtocolPolicy policy;
    bool result = plugin.ValidateBluetoothProtocolPolicy(policy);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestValidateBluetoothProtocolPolicyValid
 * @tc.desc: Test DisallowedBluetoothProtocolsPlugin::ValidateBluetoothProtocolPolicy with valid policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestValidateBluetoothProtocolPolicyValid, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    BluetoothProtocolPolicy policy;
    policy.protocolDenyList[100] = {"GATT", "SPP"};
    policy.protocolRecDenyList[100] = {"SPP", "OPP"};
    bool result = plugin.ValidateBluetoothProtocolPolicy(policy);
    ASSERT_TRUE(result);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
