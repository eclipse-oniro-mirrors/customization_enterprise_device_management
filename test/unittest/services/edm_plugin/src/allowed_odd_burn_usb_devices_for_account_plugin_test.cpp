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

#include "allowed_odd_burn_usb_devices_for_account_plugin.h"

#include "array_odd_burn_usb_device_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "iplugin.h"
#include "odd_burn_usb_device.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

namespace {
const int32_t DEVICE_VID_1 = 222;
const int32_t DEVICE_PID_1 = 333;
const int32_t DEVICE_VID_2 = 444;
const int32_t DEVICE_PID_2 = 555;
const int32_t DEVICE_VID_3 = 666;
const int32_t DEVICE_PID_3 = 777;
const int32_t TEST_ACCOUNT_ID = 101;
const std::string SERIAL_1 = "serial-account-1";

OddBurnUsbDevice MakeDevice(int32_t vid, int32_t pid, const std::string &serial = "")
{
    OddBurnUsbDevice device;
    device.SetVendorId(vid);
    device.SetProductId(pid);
    device.SetSerial(serial);
    return device;
}

bool ContainsVendor(const std::vector<OddBurnUsbDevice> &devices, int32_t vid)
{
    for (const auto &device : devices) {
        if (device.GetVendorId() == vid) {
            return true;
        }
    }
    return false;
}
} // namespace

class AllowedOddBurnUsbDevicesForAccountPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void)
    {
        Utils::SetEdmInitialEnv();
    }

    static void TearDownTestSuite(void)
    {
        Utils::ResetTokenTypeAndUid();
        ASSERT_TRUE(Utils::IsOriginalUTEnv());
    }

    void SetUp() override
    {
        plugin_ = std::make_shared<AllowedOddBurnUsbDevicesForAccountPlugin>();
    }

    void TearDown() override
    {
        plugin_.reset();
    }

    std::shared_ptr<AllowedOddBurnUsbDevicesForAccountPlugin> plugin_;
};

/**
 * @tc.name: OnSetPolicy_EmptyData_Fail
 * @tc.desc: Test OnSetPolicy returns PARAMETER_VERIFICATION_FAILED when policy data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountPluginTest, OnSetPolicy_EmptyData_Fail, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> policyData;
    std::vector<OddBurnUsbDevice> currentData;
    std::vector<OddBurnUsbDevice> mergeData;
    ErrCode ret = plugin_->OnSetPolicy(policyData, currentData, mergeData, TEST_ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_TRUE(currentData.empty());
    EXPECT_TRUE(mergeData.empty());
}

/**
 * @tc.name: OnSetPolicy_ValidData_Success
 * @tc.desc: Test OnSetPolicy unions policy data into currentData and mergeData.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountPluginTest, OnSetPolicy_ValidData_Success, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> policyData{MakeDevice(DEVICE_VID_1, DEVICE_PID_1, SERIAL_1)};
    std::vector<OddBurnUsbDevice> currentData{MakeDevice(DEVICE_VID_2, DEVICE_PID_2)};
    std::vector<OddBurnUsbDevice> mergeData;
    ErrCode ret = plugin_->OnSetPolicy(policyData, currentData, mergeData, TEST_ACCOUNT_ID);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(currentData.size(), 2u);
    EXPECT_EQ(mergeData.size(), 2u);
    EXPECT_TRUE(ContainsVendor(currentData, DEVICE_VID_1));
    EXPECT_TRUE(ContainsVendor(currentData, DEVICE_VID_2));
}

/**
 * @tc.name: OnSetPolicy_DuplicateDevice_DedupSuccess
 * @tc.desc: Test OnSetPolicy deduplicates devices already in currentData.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountPluginTest, OnSetPolicy_DuplicateDevice_DedupSuccess, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> policyData{MakeDevice(DEVICE_VID_1, DEVICE_PID_1),
        MakeDevice(DEVICE_VID_2, DEVICE_PID_2)};
    std::vector<OddBurnUsbDevice> currentData{MakeDevice(DEVICE_VID_1, DEVICE_PID_1)};
    std::vector<OddBurnUsbDevice> mergeData;
    ErrCode ret = plugin_->OnSetPolicy(policyData, currentData, mergeData, TEST_ACCOUNT_ID);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(currentData.size(), 2u);
    EXPECT_EQ(mergeData.size(), 2u);
}

/**
 * @tc.name: OnSetPolicy_WithOtherAdminMerge_UnionSuccess
 * @tc.desc: Test OnSetPolicy keeps other admin devices in mergeData after union.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountPluginTest, OnSetPolicy_WithOtherAdminMerge_UnionSuccess, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> policyData{MakeDevice(DEVICE_VID_1, DEVICE_PID_1)};
    std::vector<OddBurnUsbDevice> currentData;
    std::vector<OddBurnUsbDevice> mergeData{MakeDevice(DEVICE_VID_3, DEVICE_PID_3)};
    ErrCode ret = plugin_->OnSetPolicy(policyData, currentData, mergeData, TEST_ACCOUNT_ID);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(currentData.size(), 1u);
    EXPECT_EQ(mergeData.size(), 2u);
    EXPECT_TRUE(ContainsVendor(mergeData, DEVICE_VID_1));
    EXPECT_TRUE(ContainsVendor(mergeData, DEVICE_VID_3));
}

/**
 * @tc.name: OnSetPolicy_ExactMaxSize_Success
 * @tc.desc: Test OnSetPolicy accepts data whose size equals the max limit.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountPluginTest, OnSetPolicy_ExactMaxSize_Success, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> policyData;
    for (uint32_t i = 0; i < EdmConstants::ALLOWED_ODD_BURN_USB_DEVICES_MAX_SIZE; i++) {
        policyData.push_back(MakeDevice(static_cast<int32_t>(i), static_cast<int32_t>(i)));
    }
    std::vector<OddBurnUsbDevice> currentData;
    std::vector<OddBurnUsbDevice> mergeData;
    ErrCode ret = plugin_->OnSetPolicy(policyData, currentData, mergeData, TEST_ACCOUNT_ID);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(currentData.size(), EdmConstants::ALLOWED_ODD_BURN_USB_DEVICES_MAX_SIZE);
    EXPECT_EQ(mergeData.size(), EdmConstants::ALLOWED_ODD_BURN_USB_DEVICES_MAX_SIZE);
}

/**
 * @tc.name: OnSetPolicy_OverSize_Fail
 * @tc.desc: Test OnSetPolicy returns POLICY_LIST_OVER_SIZE when data exceeds max size.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountPluginTest, OnSetPolicy_OverSize_Fail, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> policyData;
    for (uint32_t i = 0; i <= EdmConstants::ALLOWED_ODD_BURN_USB_DEVICES_MAX_SIZE; i++) {
        policyData.push_back(MakeDevice(static_cast<int32_t>(i), static_cast<int32_t>(i)));
    }
    std::vector<OddBurnUsbDevice> currentData;
    std::vector<OddBurnUsbDevice> mergeData;
    ErrCode ret = plugin_->OnSetPolicy(policyData, currentData, mergeData, TEST_ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::POLICY_LIST_OVER_SIZE);
    EXPECT_TRUE(currentData.empty());
    EXPECT_TRUE(mergeData.empty());
}

/**
 * @tc.name: OnRemovePolicy_EmptyData_Fail
 * @tc.desc: Test OnRemovePolicy returns PARAMETER_VERIFICATION_FAILED when policy data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountPluginTest, OnRemovePolicy_EmptyData_Fail, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> policyData;
    std::vector<OddBurnUsbDevice> currentData{MakeDevice(DEVICE_VID_1, DEVICE_PID_1)};
    std::vector<OddBurnUsbDevice> mergeData{MakeDevice(DEVICE_VID_1, DEVICE_PID_1)};
    ErrCode ret = plugin_->OnRemovePolicy(policyData, currentData, mergeData, TEST_ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(currentData.size(), 1u);
    EXPECT_EQ(mergeData.size(), 1u);
}

/**
 * @tc.name: OnRemovePolicy_TargetDevice_Success
 * @tc.desc: Test OnRemovePolicy removes only the target device from currentData.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountPluginTest, OnRemovePolicy_TargetDevice_Success, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> policyData{MakeDevice(DEVICE_VID_1, DEVICE_PID_1)};
    std::vector<OddBurnUsbDevice> currentData{MakeDevice(DEVICE_VID_1, DEVICE_PID_1),
        MakeDevice(DEVICE_VID_2, DEVICE_PID_2)};
    std::vector<OddBurnUsbDevice> mergeData{MakeDevice(DEVICE_VID_1, DEVICE_PID_1),
        MakeDevice(DEVICE_VID_2, DEVICE_PID_2)};
    ErrCode ret = plugin_->OnRemovePolicy(policyData, currentData, mergeData, TEST_ACCOUNT_ID);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(currentData.size(), 1u);
    EXPECT_EQ(currentData[0].GetVendorId(), DEVICE_VID_2);
    EXPECT_TRUE(ContainsVendor(mergeData, DEVICE_VID_2));
}

/**
 * @tc.name: OnRemovePolicy_NonExistentDevice_KeepSuccess
 * @tc.desc: Test OnRemovePolicy keeps currentData unchanged when target device does not exist.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountPluginTest, OnRemovePolicy_NonExistentDevice_KeepSuccess, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> policyData{MakeDevice(DEVICE_VID_1, DEVICE_PID_1)};
    std::vector<OddBurnUsbDevice> currentData{MakeDevice(DEVICE_VID_2, DEVICE_PID_2)};
    std::vector<OddBurnUsbDevice> mergeData{MakeDevice(DEVICE_VID_2, DEVICE_PID_2)};
    ErrCode ret = plugin_->OnRemovePolicy(policyData, currentData, mergeData, TEST_ACCOUNT_ID);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(currentData.size(), 1u);
    EXPECT_EQ(currentData[0].GetVendorId(), DEVICE_VID_2);
}

/**
 * @tc.name: OnRemovePolicy_OverSize_Fail
 * @tc.desc: Test OnRemovePolicy returns POLICY_LIST_OVER_SIZE when data exceeds max size.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountPluginTest, OnRemovePolicy_OverSize_Fail, TestSize.Level1)
{
    std::vector<OddBurnUsbDevice> policyData;
    for (uint32_t i = 0; i <= EdmConstants::ALLOWED_ODD_BURN_USB_DEVICES_MAX_SIZE; i++) {
        policyData.push_back(MakeDevice(static_cast<int32_t>(i), static_cast<int32_t>(i)));
    }
    std::vector<OddBurnUsbDevice> currentData;
    std::vector<OddBurnUsbDevice> mergeData;
    ErrCode ret = plugin_->OnRemovePolicy(policyData, currentData, mergeData, TEST_ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::POLICY_LIST_OVER_SIZE);
    EXPECT_TRUE(currentData.empty());
    EXPECT_TRUE(mergeData.empty());
}

/**
 * @tc.name: InitAttribute_PolicyCodeAndName_Success
 * @tc.desc: Test plugin interface code, policy name and need-save flag.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountPluginTest, InitAttribute_PolicyCodeAndName_Success, TestSize.Level1)
{
    auto plugin = AllowedOddBurnUsbDevicesForAccountPlugin::GetPlugin();
    ASSERT_NE(plugin, nullptr);
    EXPECT_EQ(plugin->GetPolicyName(), PolicyName::POLICY_ALLOWED_ODD_BURN_USB_DEVICES_FOR_ACCOUNT);
    EXPECT_EQ(plugin->GetCode(), EdmInterfaceCode::ALLOWED_ODD_BURN_USB_DEVICES_FOR_ACCOUNT);
    EXPECT_TRUE(plugin->NeedSavePolicy());
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
