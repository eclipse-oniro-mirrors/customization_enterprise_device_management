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

#define private public
#define protected public
#include "disallowed_bluetooth_devices_plugin.h"
#undef protected
#undef private

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
class DisallowedBluetoothDevicesPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowedBluetoothDevicesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}
void DisallowedBluetoothDevicesPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSetDisallowedBluetoothDevicesEmpty
 * @tc.desc: Test set disallowed bluetooth devices function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothDevicesPluginTest, TestSetDisallowedBluetoothDevicesEmpty, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    DisallowedBluetoothDevicesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::BLUETOOTH_LIST_MAX_SIZE;
    std::vector<std::string> policyData;
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetDisallowedBluetoothDevicesWithDataAndCurrentData
 * @tc.desc: Test DisallowedBluetoothDevicesPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothDevicesPluginTest, TestSetDisallowedBluetoothDevicesWithDataAndCurrentData, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    DisallowedBluetoothDevicesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::BLUETOOTH_LIST_MAX_SIZE;
    std::vector<std::string> policyData = { "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    plugin.OnChangedPolicyDone(true);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetDisallowedBluetoothDevicesFail
 * @tc.desc: Test set disallowed bluetooth devices function.
 * @tc.type: FUNC
 */
    HWTEST_F(DisallowedBluetoothDevicesPluginTest, TestSetDisallowedBluetoothDevicesFail, TestSize.Level1)
{
    Utils::SetBluetoothDisable();
    DisallowedBluetoothDevicesPlugin devicesPlugin;
    devicesPlugin.maxListSize_ = EdmConstants::BLUETOOTH_LIST_MAX_SIZE;
    std::vector<std::string> policyData{ "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = devicesPlugin.OnBasicSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
}

/**
 * @tc.name: TestSetDisallowedBluetoothDevicesFail
 * @tc.desc: Test set disallowed bluetooth devices function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothDevicesPluginTest, TestSetDisallowedBluetoothDevicesCountFail, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    DisallowedBluetoothDevicesPlugin devicesPlugin;
    devicesPlugin.maxListSize_ = EdmConstants::BLUETOOTH_LIST_MAX_SIZE;
    std::vector<std::string> policyData(EdmConstants::BLUETOOTH_LIST_MAX_SIZE + 1);
    for (int i = 0; i < EdmConstants::BLUETOOTH_LIST_MAX_SIZE + 1; ++i) {
    std::stringstream ss;
    ss << i;
    policyData[i] = ss.str();
    }
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = devicesPlugin.OnBasicSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestRemoveDisallowedBluetoothDevicesEmpty
 * @tc.desc: Test DisallowedBluetoothDevicesPluginTest::OnRemovePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothDevicesPluginTest, TestRemoveDisallowedBluetoothDevicesEmpty, TestSize.Level1)
{
    DisallowedBluetoothDevicesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::BLUETOOTH_LIST_MAX_SIZE;
    std::vector<std::string> policyData;
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveDisallowedBluetoothDevicesWithDataAndCurrentData
 * @tc.desc: Test DisallowedBluetoothDevicesPluginTest::OnRemovePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedBluetoothDevicesPluginTest, TestRemoveDisallowedBluetoothDevicesWithDataAndCurrentData,
    TestSize.Level1)
{
    DisallowedBluetoothDevicesPlugin plugin;
    plugin.maxListSize_ = EdmConstants::BLUETOOTH_LIST_MAX_SIZE;
    std::vector<std::string> policyData = { "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    plugin.OnChangedPolicyDone(false);
    ASSERT_TRUE(ret == ERR_OK);
}
}
}
}