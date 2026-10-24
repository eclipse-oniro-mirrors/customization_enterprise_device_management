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

#define private public
#include "disallow_control_center_plugin.h"
#undef private
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE = "persist.edm.control_notification_center_disable";

class DisallowControlCenterPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowControlCenterPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowControlCenterPluginTest::TearDownTestSuite(void)
{
    system::SetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "0");
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicy
 * @tc.desc: Test DisallowControlCenterPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowControlCenterPluginTest, TestOnSetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<DisallowControlCenterPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_CONTROL_CENTER);
    system::SetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "0");

    data.WriteBool(true);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(handlePolicyData.isChanged);
    ASSERT_EQ(system::GetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "0"), "1");
}

/**
 * @tc.name: TestOnSetPolicyWithNotificationDisabled
 * @tc.desc: Test control center policy when notification center already disabled.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowControlCenterPluginTest, TestOnSetPolicyWithNotificationDisabled, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<DisallowControlCenterPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_CONTROL_CENTER);
    system::SetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "2");

    data.WriteBool(true);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(system::GetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "0"), "3");
}

/**
 * @tc.name: TestOnAdminRemove
 * @tc.desc: Test DisallowControlCenterPluginTest::OnAdminRemove function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowControlCenterPluginTest, TestOnAdminRemove, TestSize.Level1)
{
    auto plugin = std::make_shared<DisallowControlCenterPlugin>();
    bool data = true;
    bool mergeData = false;

    // only control center disabled, remove admin resets to 0
    system::SetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "1");
    ErrCode ret = plugin->OnAdminRemove("com.edm.test.admin", data, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(system::GetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "0"), "0");

    // both disabled, remove control center admin keeps notification center bit
    system::SetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "3");
    ret = plugin->OnAdminRemove("com.edm.test.admin", data, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(system::GetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "0"), "2");
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS