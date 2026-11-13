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

#include "disallow_multi_window_dock_plugin.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string PARAM_MULTI_WINDOW_DOCK_DISABLE = "persist.edm.multi_window_dock_disable";

class DisallowMultiWindowDockPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowMultiWindowDockPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowMultiWindowDockPluginTest::TearDownTestSuite(void)
{
    system::SetParameter(PARAM_MULTI_WINDOW_DOCK_DISABLE, "false");
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicy
 * @tc.desc: Test DisallowMultiWindowDockPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMultiWindowDockPluginTest, TestOnSetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    auto plugin = std::make_shared<DisallowMultiWindowDockPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_MULTI_WINDOW_DOCK);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(handlePolicyData.isChanged);
    ASSERT_EQ(system::GetParameter(PARAM_MULTI_WINDOW_DOCK_DISABLE, "false"), "true");

    data.WriteBool(false);
    HandlePolicyData handlePolicyDataAfterSet{"true", "", false};
    ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyDataAfterSet, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(handlePolicyDataAfterSet.isChanged);
    ASSERT_EQ(system::GetParameter(PARAM_MULTI_WINDOW_DOCK_DISABLE, "true"), "false");
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS