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

#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "set_usb_device_states_plugin.h"
#include "usb_device_info.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class SetUsbDeviceStatesPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void SetUsbDeviceStatesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SetUsbDeviceStatesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestOnHandlePolicyDeviceLevelCallUsb
 * @tc.desc: Test SetUsbDeviceStatesPlugin device-level calls USB Authorize.
 * @tc.type: FUNC
 */
HWTEST_F(SetUsbDeviceStatesPluginTest, TestOnHandlePolicyDeviceLevelCallUsb, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    USBDeviceConfigInfo config;
    config.busNum = 1;
    config.devAddress = 2;
    ASSERT_TRUE(config.Marshalling(data));
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = std::make_shared<SetUsbDeviceStatesPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE_NEW((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_USB_DEVICE_STATES);
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    // soft-IPC：参数合法时允许 ERR_OK / SYSTEM_ABNORMALLY / INTERFACE_UNSUPPORTED
    ASSERT_TRUE(ret == ERR_OK ||
        ret == EdmReturnErrCode::SYSTEM_ABNORMALLY ||
        ret == EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestOnHandlePolicyMismatchOptionalFail
 * @tc.desc: Test SetUsbDeviceStatesPlugin fails when only configId is set.
 * @tc.type: FUNC
 */
HWTEST_F(SetUsbDeviceStatesPluginTest, TestOnHandlePolicyMismatchOptionalFail, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    USBDeviceConfigInfo config;
    config.busNum = 1;
    config.devAddress = 2;
    config.hasConfigId = true;
    config.configId = 1;
    ASSERT_TRUE(config.Marshalling(data));
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = std::make_shared<SetUsbDeviceStatesPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE_NEW((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_USB_DEVICE_STATES);
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
