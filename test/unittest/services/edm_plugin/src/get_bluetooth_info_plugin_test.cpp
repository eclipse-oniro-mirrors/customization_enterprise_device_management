/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#include "edm_data_ability_utils_mock.h"
#include "edm_ipc_interface_code.h"
#include "get_bluetooth_info_plugin.h"
#include "bluetooth_host.h"
#include "iplugin_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const int BLUETOOTH_TURN_ON = 2;
const int32_t INVALID_BLUETOOTH_STATE = -1;

enum BluetoothState {
    TURN_OFF,
    TURNING_ON,
    TURN_ON,
    TURNING_OFF,
};

enum BluetoothConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    DISCONNECTING,
};

class GetBluetoothInfoPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void GetBluetoothInfoPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void GetBluetoothInfoPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    Bluetooth::BluetoothHost::GetDefaultHost().Close();
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: GetBluetoothInfoSuc
 * @tc.desc: Test get bluetooth info function.
 * @tc.type: FUNC
 */
HWTEST_F(GetBluetoothInfoPluginTest, GetBluetoothInfoSuc, TestSize.Level1)
{
    GetBluetoothInfoPlugin plugin;
    std::string policyValue{"GetBluetoothInfo"};
    MessageParcel data;
    MessageParcel reply;
    plugin.OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);

    std::string name = reply.ReadString();
    int state = reply.ReadInt32();
    int connectionState = reply.ReadInt32();
    ASSERT_TRUE(((state == 0) && (connectionState == 0)) ||
        ((name != "") && (state == BLUETOOTH_TURN_ON)));
}

/**
 * @tc.name: TransformBluetoothStateSuc
 * @tc.desc: Test TransformBluetoothState function.
 * @tc.type: FUNC
 */
HWTEST_F(GetBluetoothInfoPluginTest, TransformBluetoothStateSuc, TestSize.Level1)
{
    GetBluetoothInfoPlugin plugin;
    int32_t realState = plugin.TransformBluetoothState(static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURNING_ON));
    ASSERT_TRUE(realState == BluetoothState::TURNING_ON);
    realState = plugin.TransformBluetoothState(static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_ON));
    ASSERT_TRUE(realState == BluetoothState::TURN_ON);
    realState = plugin.TransformBluetoothState(static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURNING_OFF));
    ASSERT_TRUE(realState == BluetoothState::TURNING_OFF);
    realState = plugin.TransformBluetoothState(static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_OFF));
    ASSERT_TRUE(realState == BluetoothState::TURN_OFF);
    realState = plugin.TransformBluetoothState(INVALID_BLUETOOTH_STATE);
    ASSERT_TRUE(realState == INVALID_BLUETOOTH_STATE);
}

/**
 * @tc.name: TransformBluetoothConnectionStateSuc
 * @tc.desc: Test TransformBluetoothConnectionState function.
 * @tc.type: FUNC
 */
HWTEST_F(GetBluetoothInfoPluginTest, TransformBluetoothConnectionStateSuc, TestSize.Level1)
{
    GetBluetoothInfoPlugin plugin;
    int32_t realConnectionState =
        plugin.TransformBluetoothConnectionState(static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTING));
    ASSERT_TRUE(realConnectionState == BluetoothConnectionState::CONNECTING);
    realConnectionState =
        plugin.TransformBluetoothConnectionState(static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED));
    ASSERT_TRUE(realConnectionState == BluetoothConnectionState::CONNECTED);
    realConnectionState =
        plugin.TransformBluetoothConnectionState(static_cast<int32_t>(Bluetooth::BTConnectState::DISCONNECTING));
    ASSERT_TRUE(realConnectionState == BluetoothConnectionState::DISCONNECTING);
    realConnectionState =
        plugin.TransformBluetoothConnectionState(static_cast<int32_t>(Bluetooth::BTConnectState::DISCONNECTED));
    ASSERT_TRUE(realConnectionState == BluetoothConnectionState::DISCONNECTED);
    realConnectionState =
        plugin.TransformBluetoothConnectionState(INVALID_BLUETOOTH_STATE);
    ASSERT_TRUE(realConnectionState == INVALID_BLUETOOTH_STATE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS