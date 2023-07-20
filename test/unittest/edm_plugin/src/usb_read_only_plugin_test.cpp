/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "usb_read_only_plugin.h"

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class UsbReadOnlyPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void UsbReadOnlyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void UsbReadOnlyPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestUsbReadOnlyPlugin
 * @tc.desc: Test TestUsbReadOnlyPlugin::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(UsbReadOnlyPluginTest, TestUsbReadOnlyPlugin001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    // want to set usb read only
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = UsbReadOnlyPlugin::GetPlugin();
    // origin policy is allow to read write
    std::string policyData{"false"};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USB_READ_ONLY);
    bool isChanged = false;
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, policyData, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    // current policy is read only
    ASSERT_TRUE(policyData == "true");
    ASSERT_TRUE(isChanged);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS