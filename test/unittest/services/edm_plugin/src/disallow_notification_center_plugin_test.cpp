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
#include "disallow_notification_center_plugin.h"
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

class DisallowNotificationCenterPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowNotificationCenterPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowNotificationCenterPluginTest::TearDownTestSuite(void)
{
    system::SetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "0");
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicy
 * @tc.desc: Test DisallowNotificationCenterPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowNotificationCenterPluginTest, TestOnSetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<DisallowNotificationCenterPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_NOTIFICATION_CENTER);
    system::SetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "0");

    data.WriteBool(true);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(handlePolicyData.isChanged);
    ASSERT_EQ(system::GetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "0"), "2");
}

/**
 * @tc.name: TestOnSetPolicyWithControlDisabled
 * @tc.desc: Test notification center policy when control center already disabled.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowNotificationCenterPluginTest, TestOnSetPolicyWithControlDisabled, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    auto plugin = std::make_shared<DisallowNotificationCenterPlugin>();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOW_NOTIFICATION_CENTER);
    system::SetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "1");

    data.WriteBool(true);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(system::GetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "0"), "3");
}

/**
 * @tc.name: TestOnAdminRemove
 * @tc.desc: Test DisallowNotificationCenterPluginTest::OnAdminRemove function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowNotificationCenterPluginTest, TestOnAdminRemove, TestSize.Level1)
{
    auto plugin = std::make_shared<DisallowNotificationCenterPlugin>();
    bool data = true;
    bool mergeData = false;

    // only notification center disabled, remove admin resets to 0
    system::SetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "2");
    ErrCode ret = plugin->OnAdminRemove("com.edm.test.admin", data, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(system::GetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "0"), "0");

    // both disabled, remove notification center admin keeps control center bit
    system::SetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "3");
    ret = plugin->OnAdminRemove("com.edm.test.admin", data, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(system::GetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "0"), "1");
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS