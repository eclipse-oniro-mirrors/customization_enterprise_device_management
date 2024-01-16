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
#include "allowed_usb_devices_plugin.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t DEVICE_VID_1 = 222;
const int32_t DEVICE_PID_1 = 333;
const int32_t DEVICE_VID_2 = 444;
const int32_t DEVICE_PID_2 = 555;

class AllowedUsbDevicesPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void AllowedUsbDevicesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void AllowedUsbDevicesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicyEmpty
 * @tc.desc: Test AllowUsbDevicesPlugin::OnSetPolicy function when policy is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedUsbDevicesPluginTest, TestOnSetPolicyEmpty, TestSize.Level1)
{
    AllowUsbDevicesPlugin plugin;
    std::vector<UsbDeviceId> policyData;
    std::vector<UsbDeviceId> currentData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyWithDataAndCurrentData
 * @tc.desc: Test AllowUsbDevicesPlugin::OnSetPolicy function when policy has value and current data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedUsbDevicesPluginTest, TestOnSetPolicyWithDataAndCurrentData, TestSize.Level1)
{
    AllowUsbDevicesPlugin plugin;
    std::vector<UsbDeviceId> policyData;
    UsbDeviceId id1;
    id1.SetVendorId(DEVICE_VID_1);
    id1.SetProductId(DEVICE_PID_1);
    policyData.emplace_back(id1);
    std::vector<UsbDeviceId> currentData;
    UsbDeviceId id2;
    id2.SetVendorId(DEVICE_VID_2);
    id2.SetProductId(DEVICE_PID_2);
    policyData.emplace_back(id2);
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyWithDataWithoutCurrentData
 * @tc.desc: Test AllowUsbDevicesPlugin::OnSetPolicy function when policy has value and current data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedUsbDevicesPluginTest, TestOnSetPolicyWithDataWithoutCurrentData, TestSize.Level1)
{
    AllowUsbDevicesPlugin plugin;
    std::vector<UsbDeviceId> policyData;
    UsbDeviceId id;
    id.SetVendorId(DEVICE_VID_1);
    id.SetProductId(DEVICE_PID_1);
    policyData.emplace_back(id);
    std::vector<UsbDeviceId> currentData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test AllowUsbDevicesPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedUsbDevicesPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = AllowUsbDevicesPlugin::GetPlugin();
    std::string policyData{""};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemovePolicyEmpty
 * @tc.desc: Test AllowUsbDevicesPlugin::OnAdminRemove function when policy is true.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedUsbDevicesPluginTest, TestOnAdminRemovePolicyEmpty, TestSize.Level1)
{
    AllowUsbDevicesPlugin plugin;
    std::string adminName{"testAdminName"};
    std::vector<UsbDeviceId> policyData;
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveFalse
 * @tc.desc: Test AllowUsbDevicesPlugin::OnAdminRemove function when policy is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedUsbDevicesPluginTest, TestOnAdminRemoveHasPolicy, TestSize.Level1)
{
    AllowUsbDevicesPlugin plugin;
    std::string adminName{"testAdminName"};
    std::vector<UsbDeviceId> policyData;
    UsbDeviceId id;
    id.SetVendorId(DEVICE_VID_1);
    id.SetProductId(DEVICE_PID_1);
    policyData.emplace_back(id);
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS