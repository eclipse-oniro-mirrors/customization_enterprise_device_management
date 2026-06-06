/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "disallow_distributed_transmission_plugin.h"
#include "policy_manager.h"
#undef protected
#undef private

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "basic_bool_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_BUNDLE_NAME = "testBundleName";
const std::string TEST_ADMIN_NAME = "com.edm.test.demo";
const std::string TEST_POLICY_VALUE = "true";
class DisallowDistributedTransmissionPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowDistributedTransmissionPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowDistributedTransmissionPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: DisallowDistributedTransmissionOnSetPolicy
 * @tc.desc: Test DisallowDistributedTransmissionPlugin::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionPluginTest, DisallowDistributedTransmissionOnSetPolicy, TestSize.Level1)
{
    DisallowDistributedTransmissionPlugin plugin;
    bool data = true;
    bool currentData;
    bool mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    data = false;
    ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DisallowDistributedTransmissionAdminRemove
 * @tc.desc: Test DisallowDistributedTransmissionPlugin::OnAdminRemove function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionPluginTest, DisallowDistributedTransmissionAdminRemove, TestSize.Level1)
{
    DisallowDistributedTransmissionPlugin plugin;
    bool data = false;
    bool mergeData = true;
    ErrCode ret = plugin.OnAdminRemove(TEST_BUNDLE_NAME, data, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    data = true;
    mergeData = false;
    ret = plugin.OnAdminRemove(TEST_BUNDLE_NAME, data, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowDistributedTransmissionOnSetPolicyConflict
 * @tc.desc: Test DisallowDistributedTransmissionPlugin::OnSetPolicy function when conflict exists.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionPluginTest, TestDisallowDistributedTransmissionOnSetPolicyConflict,
    TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();
    ErrCode res = policyManager->SetPolicy(TEST_ADMIN_NAME, PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL,
        TEST_POLICY_VALUE, TEST_POLICY_VALUE, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    DisallowDistributedTransmissionPlugin plugin;
    bool data = true;
    bool currentData;
    bool mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    ErrCode clearRes = policyManager->SetPolicy(TEST_ADMIN_NAME,
        PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL, "", "", DEFAULT_USER_ID);
    ASSERT_TRUE(clearRes == ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestDisallowDistributedTransmissionHasConflictPolicyWithConflict
 * @tc.desc: Test DisallowDistributedTransmissionPlugin::HasConflictPolicy when conflict exists.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionPluginTest, TestDisallowDistributedTransmissionHasConflictPolicyWithConflict,
    TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();
    ErrCode res = policyManager->SetPolicy(TEST_ADMIN_NAME, PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL,
        TEST_POLICY_VALUE, TEST_POLICY_VALUE, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    DisallowDistributedTransmissionPlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    ErrCode clearRes = policyManager->SetPolicy(TEST_ADMIN_NAME,
        PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL, "", "", DEFAULT_USER_ID);
    ASSERT_TRUE(clearRes == ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestDisallowDistributedTransmissionHasConflictPolicyWithoutConflict
 * @tc.desc: Test DisallowDistributedTransmissionPlugin::HasConflictPolicy when no conflict exists.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionPluginTest, TestDisallowDistributedTransmissionHasConflictPolicyWithoutConflict,
    TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    DisallowDistributedTransmissionPlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: ClearAllowedCollaborationServiceBundles_EmptyPolicyList_Success
 * @tc.desc: Test ClearAllowedCollaborationServiceBundles when no policy exists.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionPluginTest, ClearAllowedCollaborationServiceBundles_EmptyPolicyList_Success,
    TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    DisallowDistributedTransmissionPlugin plugin;
    ErrCode ret = plugin.ClearAllowedCollaborationServiceBundles(DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: ClearAllowedCollaborationServiceBundles_SingleAdmin_Success
 * @tc.desc: Test ClearAllowedCollaborationServiceBundles with single admin policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionPluginTest, ClearAllowedCollaborationServiceBundles_SingleAdmin_Success,
    TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(TEST_ADMIN_NAME,
        PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES,
        "[\"com.test.app1\", \"com.test.app2\"]",
        "[\"com.test.app1\", \"com.test.app2\"]",
        DEFAULT_USER_ID);
    ASSERT_EQ(res, ERR_OK);

    std::string policyValue;
    res = policyManager->GetPolicy(TEST_ADMIN_NAME,
        PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES, policyValue, DEFAULT_USER_ID);
    ASSERT_EQ(res, ERR_OK);
    EXPECT_FALSE(policyValue.empty());

    DisallowDistributedTransmissionPlugin plugin;
    ErrCode ret = plugin.ClearAllowedCollaborationServiceBundles(DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: ClearAllowedCollaborationServiceBundles_MultipleAdmins_Success
 * @tc.desc: Test ClearAllowedCollaborationServiceBundles with multiple admin policies.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionPluginTest, ClearAllowedCollaborationServiceBundles_MultipleAdmins_Success,
    TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    const std::string admin1 = "com.edm.test.demo1";
    const std::string admin2 = "com.edm.test.demo2";
    const std::string policyValue1 = "[\"com.test.app1\"]";
    const std::string policyValue2 = "[\"com.test.app2\"]";

    ErrCode res = policyManager->SetPolicy(admin1,
        PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES, policyValue1, policyValue1, DEFAULT_USER_ID);
    ASSERT_EQ(res, ERR_OK);
    res = policyManager->SetPolicy(admin2,
        PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES, policyValue2, policyValue2, DEFAULT_USER_ID);
    ASSERT_EQ(res, ERR_OK);

    std::unordered_map<std::string, std::string> adminListMap;
    res = policyManager->GetAdminByPolicyName(PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES,
        adminListMap, DEFAULT_USER_ID);
    ASSERT_EQ(res, ERR_OK);
    EXPECT_EQ(adminListMap.size(), 2);

    DisallowDistributedTransmissionPlugin plugin;
    ErrCode ret = plugin.ClearAllowedCollaborationServiceBundles(DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    adminListMap.clear();
    res = policyManager->GetAdminByPolicyName(PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES,
        adminListMap, DEFAULT_USER_ID);
    EXPECT_TRUE(adminListMap.empty());

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: ClearAllowedCollaborationServiceBundles_GetAdminFailed_ReturnOK
 * @tc.desc: Test ClearAllowedCollaborationServiceBundles when GetAdminByPolicyName fails.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionPluginTest, ClearAllowedCollaborationServiceBundles_GetAdminFailed_ReturnOK,
    TestSize.Level1)
{
    DisallowDistributedTransmissionPlugin plugin;
    ErrCode ret = plugin.ClearAllowedCollaborationServiceBundles(DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: ClearAllowedCollaborationServiceBundles_AlreadyCleared_Success
 * @tc.desc: Test ClearAllowedCollaborationServiceBundles when policy already cleared.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionPluginTest, ClearAllowedCollaborationServiceBundles_AlreadyCleared_Success,
    TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(TEST_ADMIN_NAME,
        PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES, "", "", DEFAULT_USER_ID);
    ASSERT_EQ(res, ERR_OK);

    DisallowDistributedTransmissionPlugin plugin;
    ErrCode ret = plugin.ClearAllowedCollaborationServiceBundles(DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: OnSetPolicy_ClearAllowedList_Success
 * @tc.desc: Test OnSetPolicy triggers ClearAllowedCollaborationServiceBundles when data is false.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionPluginTest, OnSetPolicy_ClearAllowedList_Success, TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(TEST_ADMIN_NAME,
        PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES,
        "[\"com.test.app1\"]",
        "[\"com.test.app1\"]",
        DEFAULT_USER_ID);
    ASSERT_EQ(res, ERR_OK);

    DisallowDistributedTransmissionPlugin plugin;
    bool data = false;
    bool currentData;
    bool mergeData = false;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    std::string policyValue;
    res = policyManager->GetPolicy(TEST_ADMIN_NAME,
        PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES, policyValue, DEFAULT_USER_ID);
    EXPECT_TRUE(policyValue.empty());

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: OnSetPolicy_NoClearWhenTrue_Success
 * @tc.desc: Test OnSetPolicy does not clear allowed list when data is true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionPluginTest, OnSetPolicy_NoClearWhenTrue_Success, TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    const std::string policyValueStr = "[\"com.test.app1\"]";
    ErrCode res = policyManager->SetPolicy(TEST_ADMIN_NAME,
        PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES,
        policyValueStr, policyValueStr, DEFAULT_USER_ID);
    ASSERT_EQ(res, ERR_OK);

    DisallowDistributedTransmissionPlugin plugin;
    bool data = true;
    bool currentData;
    bool mergeData = false;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    std::string policyValue;
    res = policyManager->GetPolicy(TEST_ADMIN_NAME,
        PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES, policyValue, DEFAULT_USER_ID);
    EXPECT_EQ(policyValue, policyValueStr);

    ErrCode clearRes = policyManager->SetPolicy(TEST_ADMIN_NAME,
        PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES, "", "", DEFAULT_USER_ID);
    ASSERT_EQ(clearRes, ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
