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

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "errors.h"
#include "func_code.h"
#include "remove_notification_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
const std::string TEST_HASH_CODE = "100_0_com.example.app_1_testLabel_1700000000000";
constexpr int32_t ACCOUNT_ID = 100;
constexpr int32_t ANS_COMMON_ERR_OFFSET = ErrCodeOffset(SUBSYS_NOTIFICATION);
constexpr int32_t RET_ANS_NOT_EXIST = ANS_COMMON_ERR_OFFSET + 16;
constexpr int32_t RET_ANS_SYSTEM_LIVE_VIEW = ANS_COMMON_ERR_OFFSET + 69;
constexpr int32_t RET_ANS_USER_DELETABLE_ONLY = ANS_COMMON_ERR_OFFSET + 70;
constexpr int32_t RET_ANS_OTHER_FAILED = ANS_COMMON_ERR_OFFSET + 15;
} // namespace

class RemoveNotificationPluginMock : public RemoveNotificationPlugin {
public:
    std::string hashCode_;
    int32_t callCount_ = 0;
    int32_t ret_ = ERR_OK;

protected:
    int32_t RemoveNotification(const std::string &hashCode) override
    {
        hashCode_ = hashCode;
        callCount_++;
        return ret_;
    }
};

class RemoveNotificationPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<RemoveNotificationPluginMock> plugin_ = nullptr;

    static uint32_t SetFuncCode()
    {
        return POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
            EdmInterfaceCode::REMOVE_NOTIFICATION);
    }
};

void RemoveNotificationPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void RemoveNotificationPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

void RemoveNotificationPluginTest::SetUp()
{
    plugin_ = std::make_shared<RemoveNotificationPluginMock>();
}

void RemoveNotificationPluginTest::TearDown()
{
    plugin_.reset();
}

/**
 * @tc.name: Constructor_InitAttributes_Success
 * @tc.desc: Test RemoveNotificationPlugin construction sets expected policy attributes.
 * @tc.type: FUNC
 */
HWTEST_F(RemoveNotificationPluginTest, Constructor_InitAttributes_Success, TestSize.Level1)
{
    RemoveNotificationPlugin plugin;
    EXPECT_EQ(plugin.GetCode(), static_cast<uint32_t>(EdmInterfaceCode::REMOVE_NOTIFICATION));
    EXPECT_EQ(plugin.GetPolicyName(), PolicyName::POLICY_REMOVE_NOTIFICATION);
    EXPECT_FALSE(plugin.NeedSavePolicy());
    EXPECT_EQ(plugin.GetPermission(FuncOperateType::SET, IPlugin::PermissionType::SUPER_DEVICE_ADMIN),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NOTIFICATION);
    EXPECT_EQ(plugin.GetApiType(FuncOperateType::SET), IPlugin::ApiType::PUBLIC);
}

/**
 * @tc.name: OnHandlePolicy_EmptyHashCode_ReturnsParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy returns 9200012 and never calls ANS when hashcode is empty.
 * @tc.type: FUNC
 */
HWTEST_F(RemoveNotificationPluginTest, OnHandlePolicy_EmptyHashCode_ReturnsParameterVerificationFailed,
    TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    data.WriteString("");

    ErrCode ret = plugin_->OnHandlePolicy(SetFuncCode(), data, reply, policyData, ACCOUNT_ID);

    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(plugin_->callCount_, 0);
}

/**
 * @tc.name: OnHandlePolicy_ServiceSuccess_ReturnsErrOk
 * @tc.desc: Test OnHandlePolicy returns ERR_OK and forwards hashcode unchanged when ANS accepts the removal.
 * @tc.type: FUNC
 */
HWTEST_F(RemoveNotificationPluginTest, OnHandlePolicy_ServiceSuccess_ReturnsErrOk, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    data.WriteString(TEST_HASH_CODE);

    ErrCode ret = plugin_->OnHandlePolicy(SetFuncCode(), data, reply, policyData, ACCOUNT_ID);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(plugin_->callCount_, 1);
    EXPECT_EQ(plugin_->hashCode_, TEST_HASH_CODE);
}

/**
 * @tc.name: OnHandlePolicy_NotExist_ReturnsNotificationNotExist
 * @tc.desc: Test ANS ERR_ANS_NOTIFICATION_NOT_EXISTS maps to 9201068.
 * @tc.type: FUNC
 */
HWTEST_F(RemoveNotificationPluginTest, OnHandlePolicy_NotExist_ReturnsNotificationNotExist, TestSize.Level1)
{
    plugin_->ret_ = RET_ANS_NOT_EXIST;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    data.WriteString(TEST_HASH_CODE);

    ErrCode ret = plugin_->OnHandlePolicy(SetFuncCode(), data, reply, policyData, ACCOUNT_ID);

    EXPECT_EQ(ret, EdmReturnErrCode::NOTIFICATION_NOT_EXIST);
    EXPECT_EQ(plugin_->callCount_, 1);
}

/**
 * @tc.name: OnHandlePolicy_SystemLiveView_ReturnsNotRemovable
 * @tc.desc: Test ANS ERR_ANS_ADMIN_SYSTEM_LIVE_VIEW_NOT_REMOVABLE maps to 9201066.
 * @tc.type: FUNC
 */
HWTEST_F(RemoveNotificationPluginTest, OnHandlePolicy_SystemLiveView_ReturnsNotRemovable, TestSize.Level1)
{
    plugin_->ret_ = RET_ANS_SYSTEM_LIVE_VIEW;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    data.WriteString(TEST_HASH_CODE);

    ErrCode ret = plugin_->OnHandlePolicy(SetFuncCode(), data, reply, policyData, ACCOUNT_ID);

    EXPECT_EQ(ret, EdmReturnErrCode::NOTIFICATION_SYSTEM_LIVE_VIEW_NOT_REMOVABLE);
    EXPECT_EQ(plugin_->callCount_, 1);
}

/**
 * @tc.name: OnHandlePolicy_UserDeletableOnly_ReturnsNotRemovable
 * @tc.desc: Test ANS ERR_ANS_ADMIN_NOTIFICATION_USER_DELETABLE_ONLY maps to 9201067.
 * @tc.type: FUNC
 */
HWTEST_F(RemoveNotificationPluginTest, OnHandlePolicy_UserDeletableOnly_ReturnsNotRemovable, TestSize.Level1)
{
    plugin_->ret_ = RET_ANS_USER_DELETABLE_ONLY;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    data.WriteString(TEST_HASH_CODE);

    ErrCode ret = plugin_->OnHandlePolicy(SetFuncCode(), data, reply, policyData, ACCOUNT_ID);

    EXPECT_EQ(ret, EdmReturnErrCode::NOTIFICATION_USER_DELETABLE_ONLY);
    EXPECT_EQ(plugin_->callCount_, 1);
}

/**
 * @tc.name: OnHandlePolicy_OtherFailed_ReturnsSystemAbnormally
 * @tc.desc: Test any other ANS failure maps to 9200007, which the New channel rewrites to 9200016.
 * @tc.type: FUNC
 */
HWTEST_F(RemoveNotificationPluginTest, OnHandlePolicy_OtherFailed_ReturnsSystemAbnormally, TestSize.Level1)
{
    plugin_->ret_ = RET_ANS_OTHER_FAILED;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    data.WriteString(TEST_HASH_CODE);

    ErrCode ret = plugin_->OnHandlePolicy(SetFuncCode(), data, reply, policyData, ACCOUNT_ID);

    EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
    EXPECT_EQ(plugin_->callCount_, 1);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
