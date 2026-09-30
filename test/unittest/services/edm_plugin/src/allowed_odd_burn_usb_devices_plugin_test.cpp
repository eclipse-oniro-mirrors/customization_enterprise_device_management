/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "allowed_odd_burn_usb_devices_plugin.h"
#undef private

#include "array_odd_burn_usb_device_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "iplugin.h"
#include "ipolicy_manager.h"
#include "odd_burn_usb_device.h"
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

class AllowedOddBurnUsbDevicesPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void AllowedOddBurnUsbDevicesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void AllowedOddBurnUsbDevicesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicyEmpty
 * @tc.desc: Test AllowedOddBurnUsbDevicesPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesPluginTest, TestOnSetPolicyEmpty, TestSize.Level1)
{
    AllowedOddBurnUsbDevicesPlugin plugin;
    std::vector<OddBurnUsbDevice> policyData;
    std::vector<OddBurnUsbDevice> currentData;
    std::vector<OddBurnUsbDevice> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnSetPolicyWithData
 * @tc.desc: Test AllowedOddBurnUsbDevicesPlugin::OnSetPolicy with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesPluginTest, TestOnSetPolicyWithData, TestSize.Level1)
{
    AllowedOddBurnUsbDevicesPlugin plugin;
    std::vector<OddBurnUsbDevice> policyData;
    OddBurnUsbDevice device;
    device.SetVendorId(DEVICE_VID_1);
    device.SetProductId(DEVICE_PID_1);
    policyData.emplace_back(device);

    std::vector<OddBurnUsbDevice> currentData;
    std::vector<OddBurnUsbDevice> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_EQ(currentData.size(), 1u);
    ASSERT_EQ(mergeData.size(), 1u);
    ASSERT_EQ(currentData[0].GetVendorId(), DEVICE_VID_1);
    ASSERT_EQ(mergeData[0].GetVendorId(), DEVICE_VID_1);
}

/**
 * @tc.name: TestOnSetPolicyWithExistingCurrentData
 * @tc.desc: Test AllowedOddBurnUsbDevicesPlugin::OnSetPolicy with existing currentData (union).
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesPluginTest, TestOnSetPolicyWithExistingCurrentData, TestSize.Level1)
{
    AllowedOddBurnUsbDevicesPlugin plugin;
    std::vector<OddBurnUsbDevice> policyData;
    OddBurnUsbDevice device1;
    device1.SetVendorId(DEVICE_VID_1);
    device1.SetProductId(DEVICE_PID_1);
    policyData.emplace_back(device1);

    std::vector<OddBurnUsbDevice> currentData;
    OddBurnUsbDevice device2;
    device2.SetVendorId(DEVICE_VID_2);
    device2.SetProductId(DEVICE_PID_2);
    currentData.emplace_back(device2);

    std::vector<OddBurnUsbDevice> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_EQ(currentData.size(), 2u);
    ASSERT_EQ(mergeData.size(), 2u);
}

/**
 * @tc.name: TestOnSetPolicyOverSize
 * @tc.desc: Test AllowedOddBurnUsbDevicesPlugin::OnSetPolicy with data exceeding max size.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesPluginTest, TestOnSetPolicyOverSize, TestSize.Level1)
{
    AllowedOddBurnUsbDevicesPlugin plugin;
    std::vector<OddBurnUsbDevice> policyData;
    for (uint32_t i = 0; i <= EdmConstants::ALLOWED_ODD_BURN_USB_DEVICES_MAX_SIZE; i++) {
        OddBurnUsbDevice device;
        device.SetVendorId(static_cast<int32_t>(i));
        device.SetProductId(static_cast<int32_t>(i));
        policyData.emplace_back(device);
    }
    std::vector<OddBurnUsbDevice> currentData;
    std::vector<OddBurnUsbDevice> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::POLICY_LIST_OVER_SIZE);
}

/**
 * @tc.name: TestOnRemovePolicyEmpty
 * @tc.desc: Test AllowedOddBurnUsbDevicesPlugin::OnRemovePolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesPluginTest, TestOnRemovePolicyEmpty, TestSize.Level1)
{
    AllowedOddBurnUsbDevicesPlugin plugin;
    std::vector<OddBurnUsbDevice> policyData;
    std::vector<OddBurnUsbDevice> currentData;
    std::vector<OddBurnUsbDevice> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnRemovePolicyWithData
 * @tc.desc: Test AllowedOddBurnUsbDevicesPlugin::OnRemovePolicy with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesPluginTest, TestOnRemovePolicyWithData, TestSize.Level1)
{
    AllowedOddBurnUsbDevicesPlugin plugin;

    OddBurnUsbDevice device1;
    device1.SetVendorId(DEVICE_VID_1);
    device1.SetProductId(DEVICE_PID_1);

    OddBurnUsbDevice device2;
    device2.SetVendorId(DEVICE_VID_2);
    device2.SetProductId(DEVICE_PID_2);

    std::vector<OddBurnUsbDevice> policyData{device1};
    std::vector<OddBurnUsbDevice> currentData{device1, device2};
    std::vector<OddBurnUsbDevice> mergeData{device1, device2};
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_EQ(currentData.size(), 1u);
    ASSERT_EQ(currentData[0].GetVendorId(), DEVICE_VID_2);
}

/**
 * @tc.name: TestOnRemovePolicyOverSize
 * @tc.desc: Test AllowedOddBurnUsbDevicesPlugin::OnRemovePolicy with data exceeding max size.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesPluginTest, TestOnRemovePolicyOverSize, TestSize.Level1)
{
    AllowedOddBurnUsbDevicesPlugin plugin;
    std::vector<OddBurnUsbDevice> policyData;
    for (uint32_t i = 0; i <= EdmConstants::ALLOWED_ODD_BURN_USB_DEVICES_MAX_SIZE; i++) {
        OddBurnUsbDevice device;
        device.SetVendorId(static_cast<int32_t>(i));
        device.SetProductId(static_cast<int32_t>(i));
        policyData.emplace_back(device);
    }
    std::vector<OddBurnUsbDevice> currentData;
    std::vector<OddBurnUsbDevice> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::POLICY_LIST_OVER_SIZE);
}

/**
 * @tc.name: TestOnAdminRemoveEmpty
 * @tc.desc: Test AllowedOddBurnUsbDevicesPlugin::OnAdminRemove when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesPluginTest, TestOnAdminRemoveEmpty, TestSize.Level1)
{
    AllowedOddBurnUsbDevicesPlugin plugin;
    std::string adminName{"testAdminName"};
    std::vector<OddBurnUsbDevice> policyData;
    std::vector<OddBurnUsbDevice> mergeData;
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveWithData
 * @tc.desc: Test AllowedOddBurnUsbDevicesPlugin::OnAdminRemove with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesPluginTest, TestOnAdminRemoveWithData, TestSize.Level1)
{
    AllowedOddBurnUsbDevicesPlugin plugin;
    std::string adminName{"testAdminName"};

    OddBurnUsbDevice device1;
    device1.SetVendorId(DEVICE_VID_1);
    device1.SetProductId(DEVICE_PID_1);

    OddBurnUsbDevice device2;
    device2.SetVendorId(DEVICE_VID_2);
    device2.SetProductId(DEVICE_PID_2);

    std::vector<OddBurnUsbDevice> policyData{device1};
    std::vector<OddBurnUsbDevice> mergeData{device2};
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_EQ(mergeData.size(), 1u);
    ASSERT_EQ(mergeData[0].GetVendorId(), DEVICE_VID_1);
}

/**
 * @tc.name: TestInitPlugin
 * @tc.desc: Test AllowedOddBurnUsbDevicesPlugin::InitPlugin sets up attributes correctly.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesPluginTest, TestInitPlugin, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = AllowedOddBurnUsbDevicesPlugin::GetPlugin();
    ASSERT_NE(plugin, nullptr);
    ASSERT_EQ(plugin->GetPolicyName(), PolicyName::POLICY_ALLOWED_ODD_BURN_USB_DEVICES);
    ASSERT_EQ(plugin->GetCode(), EdmInterfaceCode::ALLOWED_ODD_BURN_USB_DEVICES);
    ASSERT_TRUE(plugin->NeedSavePolicy());
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
