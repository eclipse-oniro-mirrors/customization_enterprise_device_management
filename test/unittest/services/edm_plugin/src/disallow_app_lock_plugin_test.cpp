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
#include <string>
#include <unordered_map>
#include <vector>

#define protected public
#define private public
#include "disallow_app_lock_plugin.h"
#include "policy_manager.h"
#undef protected
#undef private

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int32_t APP_LOCK_TEST_ACCOUNT_ID = 100;
const std::string APP_LOCK_TEST_ADMIN_A = "com.edm.applock.adminA";
const std::string APP_LOCK_TEST_ADMIN_B = "com.edm.applock.adminB";
} // namespace

class DisallowAppLockPluginMock : public DisallowAppLockPlugin {
public:
    struct OtherModuleCall {
        bool policy;
        int32_t userId;
    };
    std::vector<OtherModuleCall> otherModuleCalls_;
    ErrCode otherModuleRet_ = EdmReturnErrCode::INTERFACE_UNSUPPORTED;

protected:
    ErrCode SetOtherModulePolicy(bool policy, int32_t userId) override
    {
        otherModuleCalls_.push_back({policy, userId});
        return otherModuleRet_;
    }
};

class DisallowAppLockPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<DisallowAppLockPluginMock> mock_ = nullptr;

    static uint32_t SetFuncCode()
    {
        return POLICY_FUNC_CODE_NEW(static_cast<uint32_t>(FuncOperateType::SET),
            EdmInterfaceCode::DISALLOW_APP_LOCK);
    }
};

void DisallowAppLockPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowAppLockPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

void DisallowAppLockPluginTest::SetUp()
{
    mock_ = std::make_shared<DisallowAppLockPluginMock>();
}

void DisallowAppLockPluginTest::TearDown()
{
    mock_.reset();
}

/**
 * @tc.name: DisallowAppLockPluginAttributeCheck
 * @tc.desc: Test DisallowAppLockPlugin construction sets the expected policy attributes.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAppLockPluginTest, DisallowAppLockPluginAttributeCheck, TestSize.Level1)
{
    DisallowAppLockPlugin plugin;
    EXPECT_EQ(plugin.GetCode(), static_cast<uint32_t>(EdmInterfaceCode::DISALLOW_APP_LOCK));
    EXPECT_EQ(plugin.GetPolicyName(), PolicyName::POLICY_DISALLOW_APP_LOCK);
    EXPECT_TRUE(plugin.NeedSavePolicy());
    EXPECT_EQ(plugin.GetPermission(FuncOperateType::SET, IPlugin::PermissionType::SUPER_DEVICE_ADMIN),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    EXPECT_EQ(plugin.GetApiType(FuncOperateType::SET), IPlugin::ApiType::PUBLIC);
}

/**
 * @tc.name: DisallowAppLockSetPolicyReturnUnsupported
 * @tc.desc: Test OnHandlePolicy returns 801 without the extension and leaves policyData untouched.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAppLockPluginTest, DisallowAppLockSetPolicyReturnUnsupported, TestSize.Level1)
{
    DisallowAppLockPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    data.WriteBool(true);

    ErrCode ret = plugin.OnHandlePolicy(SetFuncCode(), data, reply, policyData, APP_LOCK_TEST_ACCOUNT_ID);

    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    // policyData is not rewritten on failure, so the framework will not save it.
    EXPECT_FALSE(policyData.isChanged);
    EXPECT_EQ(policyData.policyData, "");
}

/**
 * @tc.name: DisallowAppLockReleasePolicyReturnUnsupported
 * @tc.desc: Test OnHandlePolicy also returns 801 when releasing the policy without the extension.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAppLockPluginTest, DisallowAppLockReleasePolicyReturnUnsupported, TestSize.Level1)
{
    DisallowAppLockPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    data.WriteBool(false);

    ErrCode ret = plugin.OnHandlePolicy(SetFuncCode(), data, reply, policyData, APP_LOCK_TEST_ACCOUNT_ID);

    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    EXPECT_FALSE(policyData.isChanged);
}

/**
 * @tc.name: DisallowAppLockSetFailureNoStorage
 * @tc.desc: Test no storage record of disallow_app_lock exists after the unsupported set failed.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAppLockPluginTest, DisallowAppLockSetFailureNoStorage, TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    DisallowAppLockPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    data.WriteBool(true);
    ErrCode ret = plugin.OnHandlePolicy(SetFuncCode(), data, reply, policyData, APP_LOCK_TEST_ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    EXPECT_FALSE(policyData.isChanged);

    std::unordered_map<std::string, std::string> adminValues;
    policyManager->GetAdminByPolicyName(PolicyName::POLICY_DISALLOW_APP_LOCK, adminValues,
        APP_LOCK_TEST_ACCOUNT_ID);
    // The unsupported set never leaves a storage record behind.
    EXPECT_TRUE(adminValues.empty());

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: DisallowAppLockMergeSemantics
 * @tc.desc: Test GetOthersMergePolicyData implements the OR-merge semantics for multiple admins.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAppLockPluginTest, DisallowAppLockMergeSemantics, TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();
    ASSERT_EQ(policyManager->SetPolicy(APP_LOCK_TEST_ADMIN_A, PolicyName::POLICY_DISALLOW_APP_LOCK,
        EdmConstants::CONST_TRUE, EdmConstants::CONST_TRUE, APP_LOCK_TEST_ACCOUNT_ID), ERR_OK);
    ASSERT_EQ(policyManager->SetPolicy(APP_LOCK_TEST_ADMIN_B, PolicyName::POLICY_DISALLOW_APP_LOCK,
        EdmConstants::CONST_TRUE, EdmConstants::CONST_TRUE, APP_LOCK_TEST_ACCOUNT_ID), ERR_OK);

    DisallowAppLockPlugin plugin;
    std::string mergeData;
    // Excluding admin A, admin B still keeps true, so the merged value stays true
    // (logical OR merge semantics).
    EXPECT_EQ(plugin.GetOthersMergePolicyData(APP_LOCK_TEST_ADMIN_A, APP_LOCK_TEST_ACCOUNT_ID, mergeData), ERR_OK);
    EXPECT_EQ(mergeData, EdmConstants::CONST_TRUE);

    // After clearing admin B no other admin keeps true, so the merged value is no longer true.
    ASSERT_EQ(policyManager->SetPolicy(APP_LOCK_TEST_ADMIN_B, PolicyName::POLICY_DISALLOW_APP_LOCK,
        "", "", APP_LOCK_TEST_ACCOUNT_ID), ERR_OK);
    mergeData = "";
    EXPECT_EQ(plugin.GetOthersMergePolicyData(APP_LOCK_TEST_ADMIN_A, APP_LOCK_TEST_ACCOUNT_ID, mergeData), ERR_OK);
    EXPECT_NE(mergeData, EdmConstants::CONST_TRUE);

    ASSERT_EQ(policyManager->SetPolicy(APP_LOCK_TEST_ADMIN_A, PolicyName::POLICY_DISALLOW_APP_LOCK,
        "", "", APP_LOCK_TEST_ACCOUNT_ID), ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: DisallowAppLockMergePolicyShortcut
 * @tc.desc: Test OnSetPolicy skips the external module call when the merged policy is already true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAppLockPluginTest, DisallowAppLockMergePolicyShortcut, TestSize.Level1)
{
    bool data = true;
    bool currentData = false;
    bool mergePolicy = true;
    EXPECT_EQ(mock_->OnSetPolicy(data, currentData, mergePolicy, APP_LOCK_TEST_ACCOUNT_ID), ERR_OK);
    EXPECT_TRUE(currentData);
    EXPECT_TRUE(mock_->otherModuleCalls_.empty());
}

/**
 * @tc.name: DisallowAppLockAdminRemoveRestore
 * @tc.desc: Test OnAdminRemove triggers the restore call only when no other admin keeps the policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAppLockPluginTest, DisallowAppLockAdminRemoveRestore, TestSize.Level1)
{
    // mergeData is false and data is true, so the restore call has to happen.
    mock_->otherModuleRet_ = ERR_OK; // the integrated extension plugin succeeds on restore
    bool data = true;
    bool mergeData = false;
    EXPECT_EQ(mock_->OnAdminRemove(APP_LOCK_TEST_ADMIN_A, data, mergeData, APP_LOCK_TEST_ACCOUNT_ID), ERR_OK);
    ASSERT_EQ(mock_->otherModuleCalls_.size(), 1U);
    EXPECT_FALSE(mock_->otherModuleCalls_[0].policy);
    EXPECT_EQ(mock_->otherModuleCalls_[0].userId, APP_LOCK_TEST_ACCOUNT_ID);

    // Another admin keeps the policy, so the restore call must not happen.
    mock_->otherModuleCalls_.clear();
    data = true;
    mergeData = true;
    EXPECT_EQ(mock_->OnAdminRemove(APP_LOCK_TEST_ADMIN_A, data, mergeData, APP_LOCK_TEST_ACCOUNT_ID), ERR_OK);
    EXPECT_TRUE(mock_->otherModuleCalls_.empty());
}

/**
 * @tc.name: DisallowAppLockAdminRemoveBaseUnsupported
 * @tc.desc: Test OnAdminRemove propagates 801 with the basic placeholder implementation when restore is needed.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAppLockPluginTest, DisallowAppLockAdminRemoveBaseUnsupported, TestSize.Level1)
{
    DisallowAppLockPlugin plugin;
    bool data = true;
    bool mergeData = false;
    EXPECT_EQ(plugin.OnAdminRemove(APP_LOCK_TEST_ADMIN_A, data, mergeData, APP_LOCK_TEST_ACCOUNT_ID),
        EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
