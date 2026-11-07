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

#include "disallow_power_saving_mode_plugin_test.h"

#define protected public
#define private public
#include "disallow_power_saving_mode_plugin.h"
#undef protected
#undef private
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_errors.h"
#include "iplugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void DisallowPowerSavingModePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowPowerSavingModePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDisallowPowerSavingModePluginConstructor
 * @tc.desc: Test DisallowPowerSavingModePlugin constructor sets correct policyCode, policyName and permissionConfig.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowPowerSavingModePluginTest, TestDisallowPowerSavingModePluginConstructor, TestSize.Level1)
{
    auto plugin = std::make_shared<DisallowPowerSavingModePlugin>();
    EXPECT_EQ(plugin->policyCode_, EdmInterfaceCode::DISALLOW_POWER_SAVING_MODE);
    EXPECT_EQ(plugin->policyName_, PolicyName::POLICY_DISALLOW_POWER_SAVING_MODE);
    EXPECT_EQ(plugin->permissionConfig_.apiType, IPlugin::ApiType::PUBLIC);
    auto it = plugin->permissionConfig_.typePermissions.find(IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
    ASSERT_NE(it, plugin->permissionConfig_.typePermissions.end());
    EXPECT_EQ(it->second, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
}

/**
 * @tc.name: TestDisallowPowerSavingModePluginOnHandlePolicy
 * @tc.desc: Test DisallowPowerSavingModePlugin::OnHandlePolicy returns INTERFACE_UNSUPPORTED.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowPowerSavingModePluginTest, TestDisallowPowerSavingModePluginOnHandlePolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    auto plugin = std::make_shared<DisallowPowerSavingModePlugin>();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOW_POWER_SAVING_MODE);
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestDisallowPowerSavingModePluginOnGetPolicy
 * @tc.desc: Test DisallowPowerSavingModePlugin::OnGetPolicy returns INTERFACE_UNSUPPORTED.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowPowerSavingModePluginTest, TestDisallowPowerSavingModePluginOnGetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<DisallowPowerSavingModePlugin>();
    std::string policyData;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestDisallowPowerSavingModePluginOnAdminRemove
 * @tc.desc: Test DisallowPowerSavingModePlugin::OnAdminRemove returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowPowerSavingModePluginTest, TestDisallowPowerSavingModePluginOnAdminRemove, TestSize.Level1)
{
    auto plugin = std::make_shared<DisallowPowerSavingModePlugin>();
    ErrCode ret = plugin->OnAdminRemove("com.edm.test.admin", "true", "false", DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
