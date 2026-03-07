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

#include "install_local_enterprise_app_enabled_for_account_plugin_test.h"

#define protected public
#define private public
#include "install_local_enterprise_app_enabled_for_account_plugin.h"
#undef private
#undef protected

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void InstallLocalEnterpriseAppEnabledForAccountPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void InstallLocalEnterpriseAppEnabledForAccountPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestInitPluginSuccess
 * @tc.desc: Test InstallLocalEnterpriseAppEnabledForAccountPlugin::InitPlugin success.
 * @tc.type: FUNC
 */
HWTEST_F(InstallLocalEnterpriseAppEnabledForAccountPluginTest, TestInitPluginSuccess, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = InstallLocalEnterpriseAppEnabledForAccountPlugin::GetPlugin();
    ASSERT_TRUE(plugin->IsGlobalPolicy());
    ASSERT_TRUE(plugin->NeedSavePolicy());
    ASSERT_TRUE(plugin->GetCode() ==
        (std::uint32_t)EdmInterfaceCode::INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT);
    ASSERT_EQ(plugin->GetPolicyName(), PolicyName::POLICY_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT);
    ASSERT_EQ(plugin->GetPermission(FuncOperateType::SET, IPlugin::PermissionType::SUPER_DEVICE_ADMIN),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM);
}

/**
 * @tc.name: TestOnSetPolicySetTrue
 * @tc.desc: Test InstallLocalEnterpriseAppEnabledForAccountPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(InstallLocalEnterpriseAppEnabledForAccountPluginTest, TestOnSetPolicySetTrue, TestSize.Level1)
{
    bool isEnable = true;
    bool currentdata = false;
    bool mergeData = false;
    InstallLocalEnterpriseAppEnabledForAccountPlugin plugin;
    ErrCode ret = plugin.OnSetPolicy(isEnable, currentdata, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(currentdata);
    ASSERT_TRUE(mergeData);
}

/**
 * @tc.name: TestOnSetPolicySetFalse
 * @tc.desc: Test InstallLocalEnterpriseAppEnabledForAccountPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(InstallLocalEnterpriseAppEnabledForAccountPluginTest, TestOnSetPolicySetFalse, TestSize.Level1)
{
    bool isEnable = false;
    bool currentdata = false;
    bool mergeData = false;
    InstallLocalEnterpriseAppEnabledForAccountPlugin plugin;
    ErrCode ret = plugin.OnSetPolicy(isEnable, currentdata, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(currentdata);
    ASSERT_FALSE(mergeData);
}

/**
 * @tc.name: TestOnSetPolicySetErrUserId
 * @tc.desc: Test InstallLocalEnterpriseAppEnabledForAccountPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(InstallLocalEnterpriseAppEnabledForAccountPluginTest, TestOnSetPolicySetErrUserId, TestSize.Level1)
{
    bool isEnable = false;
    bool currentdata = false;
    bool mergeData = false;
    InstallLocalEnterpriseAppEnabledForAccountPlugin plugin;
    ErrCode ret = plugin.OnSetPolicy(isEnable, currentdata, mergeData, -1);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test InstallLocalEnterpriseAppEnabledForAccountPluginTest::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(InstallLocalEnterpriseAppEnabledForAccountPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    int32_t userId = 0;
    InstallLocalEnterpriseAppEnabledForAccountPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_FALSE(reply.ReadBool());
}

/**
* @tc.name: TestOnAdminRemovePolicy
* @tc.desc: Test InstallLocalEnterpriseAppEnabledForAccountPlugin::OnAdminRemove function.
* @tc.type: FUNC
*/
HWTEST_F(InstallLocalEnterpriseAppEnabledForAccountPluginTest, TestOnAdminRemovePolicy, TestSize.Level1)
{
    std::string adminName{"testAdminName"};
    bool data = true;
    bool mergeData = false;
    InstallLocalEnterpriseAppEnabledForAccountPlugin plugin;
    ErrCode ret = plugin.OnAdminRemove(adminName, data, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS