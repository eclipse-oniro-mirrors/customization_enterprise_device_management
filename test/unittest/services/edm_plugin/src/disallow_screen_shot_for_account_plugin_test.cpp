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

#include "disallow_screen_shot_for_account_plugin.h"

#include <gtest/gtest.h>

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "policy_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisallowScreenShotForAccountPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

class TestableDisallowScreenShotForAccountPlugin : public DisallowScreenShotForAccountPlugin {
public:
    ErrCode CallCheckConflictPolicy(int32_t userId)
    {
        return this->CheckConflictPolicy(userId);
    }
};

void DisallowScreenShotForAccountPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowScreenShotForAccountPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDisallowScreenShotForAccountPluginSetTrue
 * @tc.desc: Test DisallowScreenShotForAccountPlugin::OnHandlePolicy set true success.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowScreenShotForAccountPluginTest, TestDisallowScreenShotForAccountPluginSetTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisallowScreenShotForAccountPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_SCREEN_SHOT_FOR_ACCOUNT);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);

    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(handlePolicyData.policyData, EdmConstants::CONST_TRUE);
    EXPECT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestDisallowScreenShotForAccountPluginSetFalse
 * @tc.desc: Test DisallowScreenShotForAccountPlugin::OnHandlePolicy set false success.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowScreenShotForAccountPluginTest, TestDisallowScreenShotForAccountPluginSetFalse, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisallowScreenShotForAccountPlugin>();
    HandlePolicyData handlePolicyData{"true", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_SCREEN_SHOT_FOR_ACCOUNT);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);

    ASSERT_EQ(ret, ERR_OK);
    EXPECT_TRUE(handlePolicyData.policyData.empty());
}

/**
 * @tc.name: TestDisallowScreenShotForAccountPluginCheckConflictPolicyNoConflict
 * @tc.desc: Test CheckConflictPolicy when device-level screen shot policy is not set.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowScreenShotForAccountPluginTest, TestDisallowScreenShotForAccountPluginCheckConflictPolicyNoConflict,
    TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    TestableDisallowScreenShotForAccountPlugin plugin;
    ErrCode ret = plugin.CallCheckConflictPolicy(DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestDisallowScreenShotForAccountPluginCheckConflictPolicyHasConflict
 * @tc.desc: Test CheckConflictPolicy when device-level screen shot policy is true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowScreenShotForAccountPluginTest, TestDisallowScreenShotForAccountPluginCheckConflictPolicyHasConflict,
    TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode setRes = policyManager->SetPolicy(testAdminName, PolicyName::POLICY_POLICY_SCREEN_SHOT,
        EdmConstants::CONST_TRUE, EdmConstants::CONST_TRUE, DEFAULT_USER_ID);
    ASSERT_EQ(setRes, ERR_OK);

    TestableDisallowScreenShotForAccountPlugin plugin;
    ErrCode ret = plugin.CallCheckConflictPolicy(DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    ErrCode clearRes = policyManager->SetPolicy(testAdminName, PolicyName::POLICY_POLICY_SCREEN_SHOT,
        "", "", DEFAULT_USER_ID);
    ASSERT_EQ(clearRes, ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestDisallowScreenShotForAccountPluginSetTrueConflictWithDevicePolicy
 * @tc.desc: Test OnHandlePolicy set true returns conflict when device-level policy is true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowScreenShotForAccountPluginTest, TestDisallowScreenShotForAccountPluginSetTrueConflictWithDevicePolicy,
    TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode setRes = policyManager->SetPolicy(testAdminName, PolicyName::POLICY_POLICY_SCREEN_SHOT,
        EdmConstants::CONST_TRUE, EdmConstants::CONST_TRUE, DEFAULT_USER_ID);
    ASSERT_EQ(setRes, ERR_OK);

    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisallowScreenShotForAccountPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_SCREEN_SHOT_FOR_ACCOUNT);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    ErrCode clearRes = policyManager->SetPolicy(testAdminName, PolicyName::POLICY_POLICY_SCREEN_SHOT,
        "", "", DEFAULT_USER_ID);
    ASSERT_EQ(clearRes, ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
