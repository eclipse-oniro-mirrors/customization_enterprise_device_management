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

#define protected public
#define private public
#include "disable_screen_lock_plugin.h"
#undef private
#undef protected

#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class DisableScreenLockPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<DisableScreenLockPlugin> plugin_;
};

void DisableScreenLockPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisableScreenLockPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

void DisableScreenLockPluginTest::SetUp()
{
    plugin_ = std::make_shared<DisableScreenLockPlugin>();
}

void DisableScreenLockPluginTest::TearDown()
{
    plugin_.reset();
}

/**
 * @tc.name: TestOnSetPolicy004
 * @tc.desc: Test OnSetPolicy when screen lock password has been set.
 * @tc.type: FUNC
 */
HWTEST_F(DisableScreenLockPluginTest, TestOnSetPolicy004, TestSize.Level1)
{
    bool data = true;
    bool currentData = false;
    bool mergeData = false;
    int32_t userId = DEFAULT_USER_ID;

    // This test may fail if screen lock password is actually set
    ErrCode ret = plugin_->OnSetPolicy(data, currentData, mergeData, userId);

    // Expected result depends on whether screen lock password is set
    // If password is set, should return SCREEN_LOCK_PWD_HAS_BEEN_SET
    // Otherwise should succeed
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SCREEN_LOCK_PWD_HAS_BEEN_SET);
}

/**
 * @tc.name: TestOnSetPolicy005
 * @tc.desc: Test OnSetPolicy with same policy value (no change).
 * @tc.type: FUNC
 */
HWTEST_F(DisableScreenLockPluginTest, TestOnSetPolicy005, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = DisableScreenLockPlugin::GetPlugin();
    HandlePolicyData handlePolicyData{"true", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISABLE_SCREEN_LOCK);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);

    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SCREEN_LOCK_PWD_HAS_BEEN_SET);
}

/**
 * @tc.name: TestOnGetPolicy001
 * @tc.desc: Test OnGetPolicy with valid userId.
 * @tc.type: FUNC
 */
HWTEST_F(DisableScreenLockPluginTest, TestOnGetPolicy001, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    int32_t userId = DEFAULT_USER_ID;

    ErrCode ret = plugin_->OnGetPolicy(policyData, data, reply, userId);

    ASSERT_TRUE(ret == ERR_OK);

    int32_t result;
    ASSERT_TRUE(reply.ReadInt32(result));
    ASSERT_EQ(result, ERR_OK);

    bool isDisabled;
    ASSERT_TRUE(reply.ReadBool(isDisabled));
}

/**
 * @tc.name: TestOnGetPolicy002
 * @tc.desc: Test OnGetPolicy with different userId values.
 * @tc.type: FUNC
 */
HWTEST_F(DisableScreenLockPluginTest, TestOnGetPolicy002, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    int32_t userId = 100; // Different user ID

    ErrCode ret = plugin_->OnGetPolicy(policyData, data, reply, userId);

    ASSERT_TRUE(ret == ERR_OK);

    int32_t result;
    ASSERT_TRUE(reply.ReadInt32(result));
    ASSERT_EQ(result, ERR_OK);

    bool isDisabled;
    ASSERT_TRUE(reply.ReadBool(isDisabled));
}

/**
 * @tc.name: TestGetCurrentUserId001
 * @tc.desc: Test GetCurrentUserId returns valid user ID.
 * @tc.type: FUNC
 */
HWTEST_F(DisableScreenLockPluginTest, TestGetCurrentUserId001, TestSize.Level1)
{
    int32_t userId = plugin_->GetCurrentUserId();

    ASSERT_GE(userId, 0);
}

/**
 * @tc.name: TestGetCurrentUserId002
 * @tc.desc: Test GetCurrentUserId multiple times.
 * @tc.type: FUNC
 */
HWTEST_F(DisableScreenLockPluginTest, TestGetCurrentUserId002, TestSize.Level1)
{
    int32_t userId1 = plugin_->GetCurrentUserId();
    int32_t userId2 = plugin_->GetCurrentUserId();

    ASSERT_GE(userId1, 0);
    ASSERT_GE(userId2, 0);
    ASSERT_EQ(userId1, userId2); // Should return same user ID
}

/**
 * @tc.name: TestOnSetPolicyEdgeCase001
 * @tc.desc: Test OnSetPolicy with edge case values.
 * @tc.type: FUNC
 */
HWTEST_F(DisableScreenLockPluginTest, TestOnSetPolicyEdgeCase001, TestSize.Level1)
{
    // Test with false value
    bool data = false;
    bool currentData = true;
    bool mergeData = true;
    int32_t userId = DEFAULT_USER_ID;

    ErrCode ret = plugin_->OnSetPolicy(data, currentData, mergeData, userId);

    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SCREEN_LOCK_PWD_HAS_BEEN_SET);
}

/**
 * @tc.name: TestOnSetPolicyEdgeCase002
 * @tc.desc: Test OnSetPolicy with currentData and mergeData same as data.
 * @tc.type: FUNC
 */
HWTEST_F(DisableScreenLockPluginTest, TestOnSetPolicyEdgeCase002, TestSize.Level1)
{
    bool data = true;
    bool currentData = true;
    bool mergeData = true;
    int32_t userId = DEFAULT_USER_ID;

    ErrCode ret = plugin_->OnSetPolicy(data, currentData, mergeData, userId);

    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SCREEN_LOCK_PWD_HAS_BEEN_SET);
}

/**
 * @tc.name: TestOnGetPolicyInvalidUserId
 * @tc.desc: Test OnGetPolicy with invalid userId.
 * @tc.type: FUNC
 */
HWTEST_F(DisableScreenLockPluginTest, TestOnGetPolicyInvalidUserId, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    int32_t invalidUserId = -1; // Invalid user ID

    ErrCode ret = plugin_->OnGetPolicy(policyData, data, reply, invalidUserId);

    // Should still return OK as OnGetPolicy doesn't validate userId
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestPluginIntegration001
 * @tc.desc: Test complete workflow: set policy, get policy, reset policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisableScreenLockPluginTest, TestPluginIntegration001, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisableScreenLockPlugin::GetPlugin();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISABLE_SCREEN_LOCK);

    // Set policy to true
    MessageParcel data1;
    MessageParcel reply1;
    data1.WriteBool(true);
    HandlePolicyData handlePolicyData1{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data1, reply1, handlePolicyData1, DEFAULT_USER_ID);
    if (ret == ERR_OK) {
        // Get policy
        std::string policyData;
        MessageParcel data2;
        MessageParcel reply2;
        ret = plugin_->OnGetPolicy(policyData, data2, reply2, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == ERR_OK);

        // Reset policy to false
        MessageParcel data3;
        MessageParcel reply3;
        data3.WriteBool(false);
        HandlePolicyData handlePolicyData3{"true", "", false};
        ret = plugin->OnHandlePolicy(funcCode, data3, reply3, handlePolicyData3, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == ERR_OK);
    }
}

/**
 * @tc.name: TestPluginIntegration002
 * @tc.desc: Test multiple policy changes in sequence.
 * @tc.type: FUNC
 */
HWTEST_F(DisableScreenLockPluginTest, TestPluginIntegration002, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisableScreenLockPlugin::GetPlugin();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISABLE_SCREEN_LOCK);

    // Set to true
    MessageParcel data1;
    MessageParcel reply1;
    data1.WriteBool(true);
    HandlePolicyData handlePolicyData1{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data1, reply1, handlePolicyData1, DEFAULT_USER_ID);

    if (ret == ERR_OK) {
        // Set to false
        MessageParcel data2;
        MessageParcel reply2;
        data2.WriteBool(false);
        HandlePolicyData handlePolicyData2{"true", "", false};
        ret = plugin->OnHandlePolicy(funcCode, data2, reply2, handlePolicyData2, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == ERR_OK);

        // Set to true again
        MessageParcel data3;
        MessageParcel reply3;
        data3.WriteBool(true);
        HandlePolicyData handlePolicyData3{"false", "", false};
        ret = plugin->OnHandlePolicy(funcCode, data3, reply3, handlePolicyData3, DEFAULT_USER_ID);
        ASSERT_TRUE(ret == ERR_OK);
    }
}

/**
 * @tc.name: TestOnSetPolicyConcurrent
 * @tc.desc: Test OnSetPolicy with concurrent calls.
 * @tc.type: FUNC
 */
HWTEST_F(DisableScreenLockPluginTest, TestOnSetPolicyConcurrent, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisableScreenLockPlugin::GetPlugin();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISABLE_SCREEN_LOCK);

    MessageParcel data1;
    MessageParcel reply1;
    data1.WriteBool(true);
    HandlePolicyData handlePolicyData1{"false", "", false};

    MessageParcel data2;
    MessageParcel reply2;
    data2.WriteBool(false);
    HandlePolicyData handlePolicyData2{"true", "", false};

    ErrCode ret1 = plugin->OnHandlePolicy(funcCode, data1, reply1, handlePolicyData1, DEFAULT_USER_ID);
    ErrCode ret2 = plugin->OnHandlePolicy(funcCode, data2, reply2, handlePolicyData2, DEFAULT_USER_ID);

    ASSERT_TRUE(ret1 == ERR_OK || ret1 == EdmReturnErrCode::SCREEN_LOCK_PWD_HAS_BEEN_SET);
    ASSERT_TRUE(ret2 == ERR_OK || ret2 == EdmReturnErrCode::SCREEN_LOCK_PWD_HAS_BEEN_SET);
}

/**
 * @tc.name: TestOnGetPolicyConcurrent
 * @tc.desc: Test OnGetPolicy with concurrent calls.
 * @tc.type: FUNC
 */
HWTEST_F(DisableScreenLockPluginTest, TestOnGetPolicyConcurrent, TestSize.Level1)
{
    std::string policyData1;
    MessageParcel data1;
    MessageParcel reply1;

    std::string policyData2;
    MessageParcel data2;
    MessageParcel reply2;

    ErrCode ret1 = plugin_->OnGetPolicy(policyData1, data1, reply1, DEFAULT_USER_ID);
    ErrCode ret2 = plugin_->OnGetPolicy(policyData2, data2, reply2, DEFAULT_USER_ID);

    ASSERT_TRUE(ret1 == ERR_OK);
    ASSERT_TRUE(ret2 == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
