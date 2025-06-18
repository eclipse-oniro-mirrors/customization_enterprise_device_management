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

#include "disallow_modify_ethernet_ip_plugin_test.h"

#include "disallow_modify_ethernet_ip_plugin.h"
#include "edm_ipc_interface_code.h"
#include "iplugin.h"
#include "parameters.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void DisallowModifyEthernetIpPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowModifyEthernetIpPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    OHOS::system::SetParameter(PERSIST_EDM_DISALLOW_MODIFY_ETHERNET_IP, "false");
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: DisallowModifyEthernetIpPluginTest
 * @tc.desc: Test TestDisallowModifyEthernetIpPlugin::OnSetPolicy function set true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowModifyEthernetIpPluginTest, TestDisallowModifyEthernetIpPluginSetTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = DisallowModifyEthernetIpPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOW_MODIFY_ETHERNET_IP);
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(OHOS::system::GetBoolParameter(PERSIST_EDM_DISALLOW_MODIFY_ETHERNET_IP, false));
}

/**
 * @tc.name: DisallowModifyEthernetIpPluginTest
 * @tc.desc: Test TestDisallowModifyEthernetIpPlugin::OnSetPolicy function set false.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowModifyEthernetIpPluginTest, TestDisallowModifyEthernetIpPluginSetFalse, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = DisallowModifyEthernetIpPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOW_MODIFY_ETHERNET_IP);
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(OHOS::system::GetBoolParameter(PERSIST_EDM_DISALLOW_MODIFY_ETHERNET_IP, true));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS