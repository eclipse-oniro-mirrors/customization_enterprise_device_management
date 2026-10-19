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
#include "get_patch_info_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int32_t TEST_USER_ID = 101;
}

class GetPatchInfoPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<IPlugin> plugin_ = nullptr;
};

void GetPatchInfoPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void GetPatchInfoPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

void GetPatchInfoPluginTest::SetUp()
{
    plugin_ = std::make_shared<GetPatchInfoPlugin>();
}

void GetPatchInfoPluginTest::TearDown()
{
    plugin_.reset();
}

/**
 * @tc.name: Constructor_InitAttributes_Success
 * @tc.desc: Test GetPatchInfoPlugin construction sets expected policy attributes.
 * @tc.type: FUNC
 */
HWTEST_F(GetPatchInfoPluginTest, Constructor_InitAttributes_Success, TestSize.Level1)
{
    ASSERT_NE(plugin_, nullptr);
    EXPECT_EQ(plugin_->GetCode(), static_cast<uint32_t>(EdmInterfaceCode::GET_PATCH_INFO));
    EXPECT_EQ(plugin_->GetPolicyName(), PolicyName::POLICY_GET_PATCH_INFO);
    EXPECT_FALSE(plugin_->NeedSavePolicy());
    EXPECT_EQ(plugin_->GetPermission(FuncOperateType::GET, IPlugin::PermissionType::SUPER_DEVICE_ADMIN),
        EdmPermission::PERMISSION_ENTERPRISE_GET_DEVICE_INFO);
    EXPECT_EQ(plugin_->GetApiType(FuncOperateType::GET), IPlugin::ApiType::PUBLIC);
}

/**
 * @tc.name: OnGetPolicy_OpenSourceStub_ReturnsInterfaceUnsupported
 * @tc.desc: Open-source stub OnGetPolicy returns INTERFACE_UNSUPPORTED and writes it to reply.
 * @tc.type: FUNC
 */
HWTEST_F(GetPatchInfoPluginTest, OnGetPolicy_OpenSourceStub_ReturnsInterfaceUnsupported, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    ErrCode ret = plugin_->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);

    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    int32_t replyCode = ERR_OK;
    ASSERT_TRUE(reply.ReadInt32(replyCode));
    EXPECT_EQ(replyCode, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: OnGetPolicy_EmptyPolicyData_WritesInterfaceUnsupportedToReply
 * @tc.desc: Empty policyData still returns INTERFACE_UNSUPPORTED with matching reply side effect.
 * @tc.type: FUNC
 */
HWTEST_F(GetPatchInfoPluginTest, OnGetPolicy_EmptyPolicyData_WritesInterfaceUnsupportedToReply, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    ErrCode ret = plugin_->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);

    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    EXPECT_TRUE(policyData.empty());
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: OnGetPolicy_NonEmptyPolicyData_ReturnsInterfaceUnsupported
 * @tc.desc: Non-empty policyData does not change open-source stub behavior.
 * @tc.type: FUNC
 */
HWTEST_F(GetPatchInfoPluginTest, OnGetPolicy_NonEmptyPolicyData_ReturnsInterfaceUnsupported, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::string policyData = "cached_policy";
    ErrCode ret = plugin_->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);

    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    EXPECT_EQ(policyData, "cached_policy");
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: OnGetPolicy_DifferentUserId_ReturnsInterfaceUnsupported
 * @tc.desc: Different userId does not change open-source stub behavior.
 * @tc.type: FUNC
 */
HWTEST_F(GetPatchInfoPluginTest, OnGetPolicy_DifferentUserId_ReturnsInterfaceUnsupported, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    ErrCode ret = plugin_->OnGetPolicy(policyData, data, reply, TEST_USER_ID);

    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
