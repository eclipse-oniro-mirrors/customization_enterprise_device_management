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
#include "func_code.h"
#include "remove_all_notifications_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int32_t ACCOUNT_ID = 100;
constexpr int32_t ACCOUNT_ID_INVALID = -1;
constexpr int32_t ACCOUNT_ID_MIN = 0;
constexpr int32_t RET_ANS_FAILED = 130001;
} // namespace

class RemoveAllNotificationsPluginMock : public RemoveAllNotificationsPlugin {
public:
    int32_t accountId_ = ACCOUNT_ID_INVALID;
    int32_t callCount_ = 0;
    int32_t ret_ = ERR_OK;

protected:
    int32_t RemoveAllNotifications(int32_t accountId) override
    {
        accountId_ = accountId;
        callCount_++;
        return ret_;
    }
};

class RemoveAllNotificationsPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<RemoveAllNotificationsPluginMock> plugin_ = nullptr;

    static uint32_t SetFuncCode()
    {
        return POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
            EdmInterfaceCode::REMOVE_ALL_NOTIFICATIONS);
    }
};

void RemoveAllNotificationsPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void RemoveAllNotificationsPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

void RemoveAllNotificationsPluginTest::SetUp()
{
    plugin_ = std::make_shared<RemoveAllNotificationsPluginMock>();
}

void RemoveAllNotificationsPluginTest::TearDown()
{
    plugin_.reset();
}

/**
 * @tc.name: Constructor_InitAttributes_Success
 * @tc.desc: Test RemoveAllNotificationsPlugin construction sets expected policy attributes.
 * @tc.type: FUNC
 */
HWTEST_F(RemoveAllNotificationsPluginTest, Constructor_InitAttributes_Success, TestSize.Level1)
{
    RemoveAllNotificationsPlugin plugin;
    EXPECT_EQ(plugin.GetCode(), static_cast<uint32_t>(EdmInterfaceCode::REMOVE_ALL_NOTIFICATIONS));
    EXPECT_EQ(plugin.GetPolicyName(), PolicyName::POLICY_REMOVE_ALL_NOTIFICATIONS);
    EXPECT_FALSE(plugin.NeedSavePolicy());
    EXPECT_EQ(plugin.GetPermission(FuncOperateType::SET, IPlugin::PermissionType::SUPER_DEVICE_ADMIN),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NOTIFICATION);
    EXPECT_EQ(plugin.GetApiType(FuncOperateType::SET), IPlugin::ApiType::PUBLIC);
}

/**
 * @tc.name: OnHandlePolicy_InvalidAccountId_ReturnsParameterVerificationFailed
 * @tc.desc: Test OnHandlePolicy returns 9200012 and skips the underlying service when accountId is negative.
 * @tc.type: FUNC
 */
HWTEST_F(RemoveAllNotificationsPluginTest, OnHandlePolicy_InvalidAccountId_ReturnsParameterVerificationFailed,
    TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    data.WriteInt32(ACCOUNT_ID_INVALID);

    ErrCode ret = plugin_->OnHandlePolicy(SetFuncCode(), data, reply, policyData, ACCOUNT_ID);

    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(plugin_->callCount_, 0);
    int32_t replyCode = ERR_OK;
    EXPECT_FALSE(reply.ReadInt32(replyCode));
}

/**
 * @tc.name: OnHandlePolicy_ServiceSuccess_ReturnsErrOk
 * @tc.desc: Test OnHandlePolicy returns ERR_OK when the underlying service removes notifications.
 * @tc.type: FUNC
 */
HWTEST_F(RemoveAllNotificationsPluginTest, OnHandlePolicy_ServiceSuccess_ReturnsErrOk, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    data.WriteInt32(ACCOUNT_ID);

    ErrCode ret = plugin_->OnHandlePolicy(SetFuncCode(), data, reply, policyData, ACCOUNT_ID);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(plugin_->callCount_, 1);
    EXPECT_EQ(plugin_->accountId_, ACCOUNT_ID);
    int32_t replyCode = ERR_OK;
    EXPECT_FALSE(reply.ReadInt32(replyCode));
}

/**
 * @tc.name: OnHandlePolicy_ServiceFailed_ReturnsExecuteTimeOut
 * @tc.desc: Test OnHandlePolicy returns 9200016 when the underlying service fails.
 * @tc.type: FUNC
 */
HWTEST_F(RemoveAllNotificationsPluginTest, OnHandlePolicy_ServiceFailed_ReturnsExecuteTimeOut, TestSize.Level1)
{
    plugin_->ret_ = RET_ANS_FAILED;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    data.WriteInt32(ACCOUNT_ID);

    ErrCode ret = plugin_->OnHandlePolicy(SetFuncCode(), data, reply, policyData, ACCOUNT_ID);

    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    EXPECT_EQ(plugin_->callCount_, 1);
    EXPECT_EQ(plugin_->accountId_, ACCOUNT_ID);
}

/**
 * @tc.name: OnHandlePolicy_MinValidAccountId_CallsServiceWithSameAccountId
 * @tc.desc: Test OnHandlePolicy accepts accountId 0 and passes it to the underlying service unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(RemoveAllNotificationsPluginTest, OnHandlePolicy_MinValidAccountId_CallsServiceWithSameAccountId,
    TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    data.WriteInt32(ACCOUNT_ID_MIN);

    ErrCode ret = plugin_->OnHandlePolicy(SetFuncCode(), data, reply, policyData, ACCOUNT_ID_MIN);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(plugin_->callCount_, 1);
    EXPECT_EQ(plugin_->accountId_, ACCOUNT_ID_MIN);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
