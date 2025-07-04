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

#include "switch_bluetooth_plugin_test.h"
#include "bluetooth_host.h"
#include "edm_ipc_interface_code.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void SwitchBluetoothTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SwitchBluetoothTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    Bluetooth::BluetoothHost::GetDefaultHost().Close();
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
* @tc.name: TestOpenBluetoothSuccess
* @tc.desc: Test SwitchBluetoothPlugin::OnSetPolicy function sucess.
* @tc.type: FUNC
*/
HWTEST_F(SwitchBluetoothTest, TestOpenBluetoothSuccess, TestSize.Level1)
{
    uint64_t selfTokenId = GetSelfTokenID();
    SetSelfTokenID(0);
    std::shared_ptr<IPlugin> plugin = SwitchBluetoothPlugin::GetPlugin();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SWITCH_BLUETOOTH);
    HandlePolicyData handlePolicyData{"false", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    SetSelfTokenID(selfTokenId);
}

/**
* @tc.name: TestCloseBluetoothSuccess
* @tc.desc: Test SwitchBluetoothPlugin::OnSetPolicy function sucess.
* @tc.type: FUNC
*/
HWTEST_F(SwitchBluetoothTest, TestCloseBluetoothSuccess, TestSize.Level1)
{
    uint64_t selfTokenId = GetSelfTokenID();
    SetSelfTokenID(0);
    std::shared_ptr<IPlugin> plugin = SwitchBluetoothPlugin::GetPlugin();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SWITCH_BLUETOOTH);
    HandlePolicyData handlePolicyData{"false", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    SetSelfTokenID(selfTokenId);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS