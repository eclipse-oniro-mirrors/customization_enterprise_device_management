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

#include "disallow_companion_ai_plugin.h"
#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisallowCompanionAiPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowCompanionAiPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowCompanionAiPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicy
 * @tc.desc: Test DisallowCompanionAiPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowCompanionAiPluginTest, TestOnSetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    auto plugin = std::make_shared<DisallowCompanionAiPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_COMPANION_AI);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.isChanged);
    data.WriteBool(false);
    ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test DisallowCompanionAiPluginTest::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowCompanionAiPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    auto plugin = std::make_shared<DisallowCompanionAiPlugin>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_FALSE(reply.ReadBool());
}

/**
 * @tc.name: TestSetTrueThenFalse
 * @tc.desc: Test DisallowCompanionAiPlugin set true then set false.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowCompanionAiPluginTest, TestSetTrueThenFalse, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<DisallowCompanionAiPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_COMPANION_AI);

    data.WriteBool(true);
    HandlePolicyData handlePolicyDataTrue{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyDataTrue, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyDataTrue.isChanged);

    data.WriteBool(false);
    HandlePolicyData handlePolicyDataFalse{"true", "", false};
    ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyDataFalse, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyDataFalse.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyDone
 * @tc.desc: Test DisallowCompanionAiPlugin OnHandlePolicyDone sends broadcast when isGlobalChanged is true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowCompanionAiPluginTest, TestOnHandlePolicyDone, TestSize.Level1)
{
    auto plugin = std::make_shared<DisallowCompanionAiPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_COMPANION_AI);
    plugin->OnHandlePolicyDone(funcCode, "com.example.admin", true, DEFAULT_USER_ID);
    ASSERT_TRUE(true);
}

/**
 * @tc.name: TestOnHandlePolicyDoneNotChanged
 * @tc.desc: Test DisallowCompanionAiPlugin OnHandlePolicyDone does not broadcast when isGlobalChanged is false.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowCompanionAiPluginTest, TestOnHandlePolicyDoneNotChanged, TestSize.Level1)
{
    auto plugin = std::make_shared<DisallowCompanionAiPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_COMPANION_AI);
    plugin->OnHandlePolicyDone(funcCode, "com.example.admin", false, DEFAULT_USER_ID);
    ASSERT_TRUE(true);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
