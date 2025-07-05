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

#include "disallowed_bluetooth_protocols_plugin.h"

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
 * @tc.name: TestSetDisallowedBluetoothProtocolsEmpty
 * @tc.desc: Test set disallowed nearlink protocols function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestSetDisallowedBluetoothProtocolsEmpty, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    DisallowedBluetoothProtocolsPlugin plugin;
    std::vector<std::int32_t> policyData;
    std::vector<std::int32_t> currentData;
    std::vector<std::int32_t> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestSetDisallowedBluetoothProtocolsWithDataAndCurrentData
 * @tc.desc: Test DisallowedBluetoothProtocolsPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestSetDisallowedBluetoothProtocolsWithDataAndCurrentData,
TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    DisallowedBluetoothProtocolsPlugin plugin;
    std::vector<std::int32_t> policyData = { 0, 1};
    std::vector<std::int32_t> currentData;
    std::vector<std::int32_t> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    plugin.OnChangedPolicyDone(true);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveDisallowedBluetoothProtocolsEmpty
 * @tc.desc: Test DisallowedBluetoothProtocolsPluginTest::OnRemovePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestRemoveDisallowedBluetoothProtocolsEmpty, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    std::vector<std::int32_t> policyData;
    std::vector<std::int32_t> currentData;
    std::vector<std::int32_t> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestRemoveDisallowedBluetoothProtocolsWithDataAndCurrentData
 * @tc.desc: Test DisallowedBluetoothProtocolsPluginTest::OnRemovePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestRemoveDisallowedBluetoothProtocolsWithDataAndCurrentData,
    TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    std::vector<std::int32_t> policyData = { 0, 1 };
    std::vector<std::int32_t> currentData;
    std::vector<std::int32_t> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    plugin.OnChangedPolicyDone(false);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAdminRemoveDisallowedBluetoothProtocolsEmpty
 * @tc.desc: Test DisallowedBluetoothProtocolsPluginTest::OnAdminRemovePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestAdminRemoveDisallowedBluetoothProtocolsEmpty, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    std::string adminName{"testAdminName"};
    std::vector<std::int32_t> policyData;
    std::vector<std::int32_t> mergeData;
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetPolicyDisallowedBluetoothProtocolsEmpty
 * @tc.desc: Test DisallowedBluetoothProtocolsPluginTest::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothProtocolsPluginTest, TestGetPolicyDisallowedBluetoothProtocolsEmpty, TestSize.Level1)
{
    DisallowedBluetoothProtocolsPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
}
}
}