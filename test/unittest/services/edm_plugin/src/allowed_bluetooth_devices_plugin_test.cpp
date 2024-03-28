/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "allowed_bluetooth_devices_plugin.h"
#include "edm_constants.h"
#include "edm_data_ability_utils_mock.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class AllowedBluetoothDevicesPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void AllowedBluetoothDevicesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void AllowedBluetoothDevicesPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSetBluetoothDevicesEmpty
 * @tc.desc: Test set bluetooth devices function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedBluetoothDevicesPluginTest, TestSetBluetoothDevicesEmpty, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    AllowedBluetoothDevicesPlugin plugin;
    std::vector<std::string> policyData;
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetBluetoothDevicesWithDataAndCurrentData
 * @tc.desc: Test AllowedBluetoothDevicesPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedBluetoothDevicesPluginTest, TestSetBluetoothDevicesWithDataAndCurrentData, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    AllowedBluetoothDevicesPlugin plugin;
    std::vector<std::string> policyData = { "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    std::vector<std::string> currentData = { "00:00:5E:00:53:00", "FF:FF:FF:FF:FF:FF" };
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetBluetoothDevicesWithDataWithoutCurrentData
 * @tc.desc: Test AllowedBluetoothDevicesPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedBluetoothDevicesPluginTest, TestSetBluetoothDevicesWithDataWithoutCurrentData, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    AllowedBluetoothDevicesPlugin plugin;
    std::vector<std::string> policyData = { "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetBluetoothDevicesFail
 * @tc.desc: Test set bluetooth devices function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedBluetoothDevicesPluginTest, TestSetBluetoothDevicesFail, TestSize.Level1)
{
    Utils::SetBluetoothDisable();
    AllowedBluetoothDevicesPlugin devicesPlugin;
    std::vector<std::string> policyData{ "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    std::vector<std::string> currentData;
    ErrCode ret = devicesPlugin.OnSetPolicy(policyData, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
}

/**
 * @tc.name: TestSetBluetoothDevicesFail
 * @tc.desc: Test set bluetooth devices function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedBluetoothDevicesPluginTest, TestSetBluetoothDevicesCountFail, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    AllowedBluetoothDevicesPlugin devicesPlugin;
    std::vector<std::string> policyData(EdmConstants::BLUETOOTH_WHITELIST_MAX_SIZE + 1);
    for (int i = 0; i < EdmConstants::BLUETOOTH_WHITELIST_MAX_SIZE + 1; ++i) {
        std::stringstream ss;
        ss << i;
        policyData[i] = ss.str();
    }
    std::vector<std::string> currentData;
    ErrCode ret = devicesPlugin.OnSetPolicy(policyData, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestGetBluetoothDevicesSuc
 * @tc.desc: Test AllowedBluetoothDevicesPluginTest::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedBluetoothDevicesPluginTest, TestGetBluetoothDevicesSuc, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = AllowedBluetoothDevicesPlugin::GetPlugin();
    std::string policyValue{ "GetBluetoothDevices" };
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveBluetoothDevicesEmpty
 * @tc.desc: Test AllowedBluetoothDevicesPluginTest::OnRemovePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedBluetoothDevicesPluginTest, TestRemoveBluetoothDevicesEmpty, TestSize.Level1)
{
    AllowedBluetoothDevicesPlugin plugin;
    std::vector<std::string> policyData;
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveBluetoothDevicesWithDataAndCurrentData
 * @tc.desc: Test AllowedBluetoothDevicesPluginTest::OnRemovePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedBluetoothDevicesPluginTest, TestRemoveBluetoothDevicesWithDataAndCurrentData, TestSize.Level1)
{
    AllowedBluetoothDevicesPlugin plugin;
    std::vector<std::string> policyData = { "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    std::vector<std::string> currentData = { "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveBluetoothDevicesWithDataWithoutCurrentData
 * @tc.desc: Test AllowedBluetoothDevicesPluginTest::OnRemovePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedBluetoothDevicesPluginTest, TestRemoveBluetoothDevicesWithDataWithoutCurrentData, TestSize.Level1)
{
    AllowedBluetoothDevicesPlugin plugin;
    std::vector<std::string> policyData = { "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS