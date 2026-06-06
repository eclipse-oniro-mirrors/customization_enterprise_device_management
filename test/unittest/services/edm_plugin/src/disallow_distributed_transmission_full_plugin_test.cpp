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
#include "disallow_distributed_transmission_full_plugin.h"
#include "policy_manager.h"
#undef protected
#undef private

#include "edm_constants.h"
#include "edm_data_ability_utils_mock.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_BUNDLE_NAME = "testBundleName";
const std::string TEST_ADMIN_NAME = "com.edm.test.demo";
const std::string TEST_POLICY_VALUE = "true";
class DisallowDistributedTransmissionFullPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowDistributedTransmissionFullPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowDistributedTransmissionFullPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullOnSetPolicyTrue
 * @tc.desc: Test DisallowDistributedTransmissionFullPlugin::OnSetPolicy function with true value.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullPluginTest, TestDisallowDistributedTransmissionFullOnSetPolicyTrue,
    TestSize.Level1)
{
    DisallowDistributedTransmissionFullPlugin plugin;
    bool data = true;
    bool currentData;
    bool mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullOnSetPolicyFalse
 * @tc.desc: Test DisallowDistributedTransmissionFullPlugin::OnSetPolicy function with false value.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullPluginTest, TestDisallowDistributedTransmissionFullOnSetPolicyFalse,
    TestSize.Level1)
{
    DisallowDistributedTransmissionFullPlugin plugin;
    bool data = false;
    bool currentData;
    bool mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    ASSERT_TRUE(currentData == false);
    ASSERT_TRUE(mergeData == false);
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullOnSetPolicyWithMerge
 * @tc.desc: Test DisallowDistributedTransmissionFullPlugin::OnSetPolicy function with mergeData true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullPluginTest, TestDisallowDistributedTransmissionFullOnSetPolicyWithMerge,
    TestSize.Level1)
{
    DisallowDistributedTransmissionFullPlugin plugin;
    bool data = true;
    bool currentData = false;
    bool mergeData = true;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(currentData == true);
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullOnSetPolicyConflict
 * @tc.desc: Test DisallowDistributedTransmissionFullPlugin::OnSetPolicy function when conflict exists.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullPluginTest, TestDisallowDistributedTransmissionFullOnSetPolicyConflict,
    TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();
    ErrCode res = policyManager->SetPolicy(TEST_ADMIN_NAME, PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION,
        TEST_POLICY_VALUE, TEST_POLICY_VALUE, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    DisallowDistributedTransmissionFullPlugin plugin;
    bool data = true;
    bool currentData;
    bool mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    ErrCode clearRes = policyManager->SetPolicy(TEST_ADMIN_NAME, PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION,
        "", "", DEFAULT_USER_ID);
    ASSERT_TRUE(clearRes == ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullOnAdminRemoveWithMerge
 * @tc.desc: Test DisallowDistributedTransmissionFullPlugin::OnAdminRemove function with mergeData true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullPluginTest, TestDisallowDistributedTransmissionFullOnAdminRemoveWithMerge,
    TestSize.Level1)
{
    DisallowDistributedTransmissionFullPlugin plugin;
    bool data = true;
    bool mergeData = true;
    ErrCode ret = plugin.OnAdminRemove(TEST_BUNDLE_NAME, data, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullOnAdminRemoveWithDataTrue
 * @tc.desc: Test DisallowDistributedTransmissionFullPlugin::OnAdminRemove function with data true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullPluginTest,
    TestDisallowDistributedTransmissionFullOnAdminRemoveWithDataTrue, TestSize.Level1)
{
    DisallowDistributedTransmissionFullPlugin plugin;
    bool data = true;
    bool mergeData = false;
    ErrCode ret = plugin.OnAdminRemove(TEST_BUNDLE_NAME, data, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullOnAdminRemoveWithDataFalse
 * @tc.desc: Test DisallowDistributedTransmissionFullPlugin::OnAdminRemove function with data false.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullPluginTest,
    TestDisallowDistributedTransmissionFullOnAdminRemoveWithDataFalse, TestSize.Level1)
{
    DisallowDistributedTransmissionFullPlugin plugin;
    bool data = false;
    bool mergeData = false;
    ErrCode ret = plugin.OnAdminRemove(TEST_BUNDLE_NAME, data, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullHasConflictPolicyWithConflict
 * @tc.desc: Test DisallowDistributedTransmissionFullPlugin::HasConflictPolicy when conflict exists.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullPluginTest,
    TestDisallowDistributedTransmissionFullHasConflictPolicyWithConflict, TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();
    ErrCode res = policyManager->SetPolicy(TEST_ADMIN_NAME, PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION,
        TEST_POLICY_VALUE, TEST_POLICY_VALUE, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    DisallowDistributedTransmissionFullPlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    ErrCode clearRes = policyManager->SetPolicy(TEST_ADMIN_NAME, PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION,
        "", "", DEFAULT_USER_ID);
    ASSERT_TRUE(clearRes == ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullHasConflictPolicyWithoutConflict
 * @tc.desc: Test DisallowDistributedTransmissionFullPlugin::HasConflictPolicy when no conflict exists.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullPluginTest,
    TestDisallowDistributedTransmissionFullHasConflictPolicyWithoutConflict, TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    DisallowDistributedTransmissionFullPlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullSetOtherModulePolicyTrue
 * @tc.desc: Test DisallowDistributedTransmissionFullPlugin::SetOtherModulePolicy with true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullPluginTest,
    TestDisallowDistributedTransmissionFullSetOtherModulePolicyTrue, TestSize.Level1)
{
    DisallowDistributedTransmissionFullPlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK || ret == 4194327);
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullSetOtherModulePolicyFalse
 * @tc.desc: Test DisallowDistributedTransmissionFullPlugin::SetOtherModulePolicy with false.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullPluginTest,
    TestDisallowDistributedTransmissionFullSetOtherModulePolicyFalse, TestSize.Level1)
{
    DisallowDistributedTransmissionFullPlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(false, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK || ret == 4194327);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
