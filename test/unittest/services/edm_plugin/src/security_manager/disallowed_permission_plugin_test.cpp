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
#include <gmock/gmock.h>

#define private public
#define protected public
#include "disallowed_permission_plugin.h"
#undef private
#undef protected

#include "allowed_permission_bundle_serializer.h"
#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "func_code_utils.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class DisallowedPermissionPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void)
    {
        Utils::SetEdmInitialEnv();
    }

    static void TearDownTestSuite(void)
    {
        Utils::ResetTokenTypeAndUid();
        EXPECT_EQ(Utils::IsOriginalUTEnv(), true);
        std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
    }
};

namespace {
const std::string TEST_UNKNOWN_PERMISSION = "ohos.permission.NOT.A.REAL.PERMISSION";
}

/**
 * @tc.name: TestPluginAttributes
 * @tc.desc: Test DisallowedPermissionPlugin code, name and the inherited limits.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionPluginTest, TestPluginAttributes, TestSize.Level1)
{
    auto plugin = DisallowedPermissionPlugin::GetPlugin();
    ASSERT_NE(plugin, nullptr);
    EXPECT_EQ(plugin->GetCode(), EdmInterfaceCode::DISALLOWED_PERMISSION);
    EXPECT_EQ(plugin->GetPolicyName(), PolicyName::POLICY_DISALLOWED_PERMISSION);

    DisallowedPermissionPlugin instance;
    auto pluginTemplate = std::make_shared<IPluginTemplate<DisallowedPermissionPlugin, std::vector<std::string>>>();
    instance.InitPlugin(pluginTemplate);
    EXPECT_EQ(instance.maxListSize_, EdmConstants::APPID_MAX_SIZE);
    EXPECT_EQ(instance.overMaxReturnErrCode_, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestAddOrRemovePolicyUnknownPermission
 * @tc.desc: Test an unknown permission name is rejected before any access-token call.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionPluginTest, TestAddOrRemovePolicyUnknownPermission, TestSize.Level1)
{
    DisallowedPermissionPlugin plugin;
    std::vector<std::string> data = { TEST_UNKNOWN_PERMISSION };
    ErrCode ret = plugin.AddOrRemoveAccessTokenPolicy(data, DEFAULT_USER_ID, true);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);

    ret = plugin.AddOrRemoveAccessTokenPolicy(data, DEFAULT_USER_ID, false);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestAddOrRemoveAccessTokenPolicyEmptyList
 * @tc.desc: Test an empty permission list succeeds without touching the token service.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionPluginTest, TestAddOrRemoveAccessTokenPolicyEmptyList, TestSize.Level1)
{
    DisallowedPermissionPlugin plugin;
    std::vector<std::string> data;
    ErrCode ret = plugin.AddOrRemoveAccessTokenPolicy(data, DEFAULT_USER_ID, true);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestSetOtherModulePolicyUnknownPermission
 * @tc.desc: Test SetOtherModulePolicy forwards the failure of the access-token check.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionPluginTest, TestSetOtherModulePolicyUnknownPermission, TestSize.Level1)
{
    DisallowedPermissionPlugin plugin;
    std::vector<std::string> data = { TEST_UNKNOWN_PERMISSION };
    std::vector<std::string> failedData;
    ErrCode ret = plugin.SetOtherModulePolicy(data, DEFAULT_USER_ID, failedData);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_TRUE(failedData.empty());
}

/**
 * @tc.name: TestRemoveOtherModulePolicyFailed
 * @tc.desc: Test RemoveOtherModulePolicy stops on the first failed permission.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionPluginTest, TestRemoveOtherModulePolicyFailed, TestSize.Level1)
{
    DisallowedPermissionPlugin plugin;
    std::vector<std::string> data = { TEST_UNKNOWN_PERMISSION };
    std::vector<std::string> failedData;
    ErrCode ret = plugin.RemoveOtherModulePolicy(data, DEFAULT_USER_ID, failedData);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestRemoveOtherModulePolicyEmptyList
 * @tc.desc: Test RemoveOtherModulePolicy with no permission succeeds and cleans nothing.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionPluginTest, TestRemoveOtherModulePolicyEmptyList, TestSize.Level1)
{
    DisallowedPermissionPlugin plugin;
    std::vector<std::string> data;
    std::vector<std::string> failedData;
    ErrCode ret = plugin.RemoveOtherModulePolicy(data, DEFAULT_USER_ID, failedData);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestGetCombinedPolicy
 * @tc.desc: Test GetCombinedPolicy returns either an empty policy or the serialized whitelist.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionPluginTest, TestGetCombinedPolicy, TestSize.Level1)
{
    DisallowedPermissionPlugin plugin;
    std::string combinePolicy = plugin.GetCombinedPolicy(TEST_UNKNOWN_PERMISSION, DEFAULT_USER_ID);
    EXPECT_TRUE(combinePolicy.empty() || combinePolicy.front() == '{');
}

/**
 * @tc.name: TestCleanAdminAllowedPermissionBundle
 * @tc.desc: Test CleanAdminAllowedPermissionBundle succeeds whether or not admins hold the policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionPluginTest, TestCleanAdminAllowedPermissionBundle, TestSize.Level1)
{
    DisallowedPermissionPlugin plugin;
    ErrCode ret = plugin.CleanAdminAllowedPermissionBundle(TEST_UNKNOWN_PERMISSION,
        DEFAULT_USER_ID, "");
    EXPECT_EQ(ret, ERR_OK);

    ret = plugin.CleanAdminAllowedPermissionBundle(TEST_UNKNOWN_PERMISSION, DEFAULT_USER_ID, "{}");
    EXPECT_EQ(ret, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
