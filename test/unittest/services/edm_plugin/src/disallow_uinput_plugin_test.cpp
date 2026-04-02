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

#include <gtest/gtest.h>

#define private public
#include "disallow_uinput_plugin.h"
#undef private
#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisallowUInputPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowUInputPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowUInputPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: DisallowUInputPluginOnSetPolicy
 * @tc.desc: Test DisallowUInputPlugin::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowUInputPluginTest, DisallowUInputPluginOnSetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    auto plugin = DisallowUInputPlugin::GetPlugin();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_UINPUT);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DisallowUInputPluginSetOtherModulePolicy
 * @tc.desc: Test DisallowUInputPlugin::SetOtherModulePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowUInputPluginTest, DisallowUInputPluginSetOtherModulePolicy, TestSize.Level1)
{
    DisallowUInputPlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ret = plugin.SetOtherModulePolicy(false, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DisallowUInputPluginRemoveOtherModulePolicy
 * @tc.desc: Test DisallowUInputPlugin::RemoveOtherModulePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowUInputPluginTest, DisallowUInputPluginRemoveOtherModulePolicy, TestSize.Level1)
{
    DisallowUInputPlugin plugin;
    ErrCode ret = plugin.RemoveOtherModulePolicy(DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS