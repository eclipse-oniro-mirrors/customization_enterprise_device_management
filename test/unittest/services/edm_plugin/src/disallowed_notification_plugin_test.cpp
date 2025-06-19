/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "disallowed_notification_plugin_test.h"

#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void DisallowedNotificationPluginTest::SetUpTestSuite(void) {}
void DisallowedNotificationPluginTest::TearDownTestSuite(void) {}

/**
 * @tc.name: TestDisallowedNotificationPlugin001
 * @tc.desc: Test DisallowedNotificationPlugin::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedNotificationPluginTest, TestDisallowedNotificationPlugin001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = DisallowedNotificationPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_NOTIFICATION);
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "true");
    ASSERT_TRUE(handlePolicyData.isChanged);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS