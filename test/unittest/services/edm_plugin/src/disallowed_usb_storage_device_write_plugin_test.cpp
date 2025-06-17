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
#include "disallowed_usb_storage_device_write_plugin_test.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisableUsbStorageDeviceWritePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisableUsbStorageDeviceWritePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisableUsbStorageDeviceWritePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDisableUsbStorageDeviceWritePluginTestSet
 * @tc.desc: Test DisableUsbStorageDeviceWritePluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisableUsbStorageDeviceWritePluginTest, TestDisableUsbStorageDeviceWritePluginTestSet, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = DisableUsbStorageDeviceWritePlugin::GetPlugin();
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "true");
    ASSERT_TRUE(handlePolicyData.isChanged);

    // 恢复环境，取消禁用
    MessageParcel dataFalse;
    dataFalse.WriteBool(false);
    HandlePolicyData handlePolicyDataFalse{"true", "", false};
    ret = plugin->OnHandlePolicy(funcCode, dataFalse, reply, handlePolicyDataFalse, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS