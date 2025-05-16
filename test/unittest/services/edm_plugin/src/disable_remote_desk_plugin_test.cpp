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
#include "disable_remote_desk_plugin.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string PERSIST_EDM_REMOTE_DESK_MODE = "persist.edm.remote_desk_disable";
class DisableRemoteDeskPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisableRemoteDeskPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisableRemoteDeskPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDisableRemoteDeskPluginTestSetTrue
 * @tc.desc: Test DisableRemoteDeskPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisableRemoteDeskPluginTest, TestDisableRemoteDeskPluginTestSetTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = DisableRemoteDeskPlugin::GetPlugin();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISABLE_REMOTE_DESK);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "true");
    ASSERT_TRUE(OHOS::system::GetBoolParameter(PERSIST_EDM_REMOTE_DESK_MODE, false));
}

/**
 * @tc.name: TestDisableRemoteDeskPluginTestSetFalse
 * @tc.desc: Test DisableRemoteDeskPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisableRemoteDeskPluginTest, TestDisableRemoteDeskPluginTestSetFalse, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = DisableRemoteDeskPlugin::GetPlugin();
    HandlePolicyData handlePolicyData{"true", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISABLE_REMOTE_DESK);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "false");
    ASSERT_FALSE(OHOS::system::GetBoolParameter(PERSIST_EDM_REMOTE_DESK_MODE, true));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS