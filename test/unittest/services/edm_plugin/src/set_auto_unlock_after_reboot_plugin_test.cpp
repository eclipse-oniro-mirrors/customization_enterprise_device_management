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

#include "set_auto_unlock_after_reboot_plugin_test.h"

#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"
#include "plugin_singleton.h"
#include "set_auto_unlock_after_reboot_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string PERSIST_EDM_REMOTE_AUTO_UNLOCK_MODE = "persist.edm.auto_unlock_after_reboot";
void SetAutoUnlockAfterRebootPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SetAutoUnlockAfterRebootPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    OHOS::system::SetParameter(PERSIST_EDM_REMOTE_AUTO_UNLOCK_MODE, "false");
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSetAutoUnlockAfterRebootPluginTestSetTrue
 * @tc.desc: Test SetAutoUnlockAfterRebootPluginTest OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetAutoUnlockAfterRebootPluginTest, TestSetAutoUnlockAfterRebootPluginTestSetTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = SetAutoUnlockAfterRebootPlugin::GetPlugin();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_AUTO_UNLOCK_AFTER_REBOOT);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(OHOS::system::GetBoolParameter(PERSIST_EDM_REMOTE_AUTO_UNLOCK_MODE, false));
}
 
/**
 * @tc.name: TestSetAutoUnlockAfterRebootPluginTestSetFalse
 * @tc.desc: Test SetAutoUnlockAfterRebootPluginTest OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetAutoUnlockAfterRebootPluginTest, TestSetAutoUnlockAfterRebootPluginTestSetFalse, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = SetAutoUnlockAfterRebootPlugin::GetPlugin();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_AUTO_UNLOCK_AFTER_REBOOT);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(OHOS::system::GetBoolParameter(PERSIST_EDM_REMOTE_AUTO_UNLOCK_MODE, true));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
