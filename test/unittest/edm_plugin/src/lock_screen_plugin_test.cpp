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

#include "lock_screen_plugin_test.h"
#include "edm_ipc_interface_code.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void LockScreenPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void LockScreenPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestLockScreen
 * @tc.desc: Test LockScreenPlugin::OnSetPolicy function fail.
 * @tc.type: FUNC
 */
HWTEST_F(LockScreenPluginTest, TestLockScreen, TestSize.Level1)
{
    Utils::ResetTokenTypeAndUid();
    std::shared_ptr<IPlugin> plugin = LockScreenPlugin::GetPlugin();
    bool isChanged = false;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::LOCK_SCREEN);
    std::string policyData{""};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, policyData, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
