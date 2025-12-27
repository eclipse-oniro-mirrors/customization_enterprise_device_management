/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "set_ability_disable_plugin.h"

#include <gtest/gtest.h>

#include "edm_data_ability_utils_mock.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class SetAbilityDisablePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SetAbilityDisablePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void SetAbilityDisablePluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicy_001
 * @tc.desc: Test OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetAbilityDisablePluginTest, TestOnSetPolicy_001, TestSize.Level1)
{
    std::shared_ptr<SetAbilityDisablePlugin> plugin = std::make_shared<SetAbilityDisablePlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_ABILITY_ENABLED);
    HandlePolicyData handlePolicyData{"", "", false};

    MessageParcel data;
    MessageParcel reply;
    data.WriteString("com.example.helloworld");
    data.WriteString("EntryAbility");
    data.WriteBool(true);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnSetPolicy_002
 * @tc.desc: Test OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetAbilityDisablePluginTest, TestOnSetPolicy_002, TestSize.Level1)
{
    std::shared_ptr<SetAbilityDisablePlugin> plugin = std::make_shared<SetAbilityDisablePlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_ABILITY_ENABLED);
    HandlePolicyData handlePolicyData{"[\"com.example.helloworld/EntryAbility\"]", "", false};

    MessageParcel data;
    MessageParcel reply;
    data.WriteString("com.example.helloworld");
    data.WriteString("EntryAbility");
    data.WriteBool(true);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicy_003
 * @tc.desc: Test OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetAbilityDisablePluginTest, TestOnSetPolicy_003, TestSize.Level1)
{
    std::shared_ptr<SetAbilityDisablePlugin> plugin = std::make_shared<SetAbilityDisablePlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_ABILITY_ENABLED);
    HandlePolicyData handlePolicyData{"", "[\"com.example.helloworld/EntryAbility\"]", false};

    MessageParcel data;
    MessageParcel reply;
    data.WriteString("com.example.helloworld");
    data.WriteString("EntryAbility");
    data.WriteBool(true);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicy_004
 * @tc.desc: Test OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetAbilityDisablePluginTest, TestOnSetPolicy_004, TestSize.Level1)
{
    std::shared_ptr<SetAbilityDisablePlugin> plugin = std::make_shared<SetAbilityDisablePlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_ABILITY_ENABLED);
    HandlePolicyData handlePolicyData{"", "[\"com.example.helloworld/EntryAbility\"]", false};

    MessageParcel data;
    MessageParcel reply;
    data.WriteString("com.example.helloworld");
    data.WriteString("EntryAbility");
    data.WriteBool(false);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicy_005
 * @tc.desc: Test OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetAbilityDisablePluginTest, TestOnSetPolicy_005, TestSize.Level1)
{
    std::shared_ptr<SetAbilityDisablePlugin> plugin = std::make_shared<SetAbilityDisablePlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_ABILITY_ENABLED);
    HandlePolicyData handlePolicyData{"[\"com.example.helloworld/EntryAbility\"]",
        "[\"com.example.helloworld/EntryAbility\"]", false};

    MessageParcel data;
    MessageParcel reply;
    data.WriteString("com.example.helloworld");
    data.WriteString("EntryAbility");
    data.WriteBool(false);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicy_006
 * @tc.desc: Test OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetAbilityDisablePluginTest, TestOnSetPolicy_006, TestSize.Level1)
{
    std::shared_ptr<SetAbilityDisablePlugin> plugin = std::make_shared<SetAbilityDisablePlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_ABILITY_ENABLED);
    HandlePolicyData handlePolicyData{"[\"com.example.helloworld/EntryAbility\"]", "", false};

    MessageParcel data;
    MessageParcel reply;
    data.WriteString("com.example.helloworld");
    data.WriteString("EntryAbility");
    data.WriteBool(false);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnSetPolicy_007
 * @tc.desc: Test OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetAbilityDisablePluginTest, TestOnSetPolicy_007, TestSize.Level1)
{
    std::shared_ptr<SetAbilityDisablePlugin> plugin = std::make_shared<SetAbilityDisablePlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::SET_ABILITY_ENABLED);
    HandlePolicyData handlePolicyData{"[\"com.example.helloworld/EntryAbility\"]", "", false};

    MessageParcel data;
    MessageParcel reply;
    data.WriteString("com.example.helloworld");
    data.WriteString("EntryAbility");
    data.WriteBool(true);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetAbilityDisablePluginTest, TestOnGetPolicy_001, TestSize.Level1)
{
    std::shared_ptr<SetAbilityDisablePlugin> plugin = std::make_shared<SetAbilityDisablePlugin>();
    std::string policyValue{"[\"com.example.helloworld/EntryAbility\"]"};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("com.example.helloworld");
    data.WriteString("EntryAbility1");
    ErrCode code = plugin->OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(code, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_FALSE(reply.ReadBool());
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetAbilityDisablePluginTest, TestOnGetPolicy_002, TestSize.Level1)
{
    std::shared_ptr<SetAbilityDisablePlugin> plugin = std::make_shared<SetAbilityDisablePlugin>();
    std::string policyValue{"[\"com.example.helloworld/EntryAbility\"]"};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("com.example.helloworld");
    data.WriteString("EntryAbility");
    ErrCode code = plugin->OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(code, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_TRUE(reply.ReadBool());
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS