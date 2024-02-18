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
 * @tc.name: TestUsbReadOnlyPlugin001
 * @tc.desc: Test UsbReadOnlyPlugin::OnSetPolicy function to set usb read only.
 * @tc.type: FUNC
 */
HWTEST_F(UsbReadOnlyPluginTest, TestUsbReadOnlyPlugin001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    // want to set usb read only
    data.WriteInt32(1);
    std::shared_ptr<IPlugin> plugin = UsbReadOnlyPlugin::GetPlugin();
    // origin policy is allowed to read write
    HandlePolicyData handlePolicyData{"0", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USB_READ_ONLY);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    // current policy is read only
    ASSERT_TRUE(handlePolicyData.policyData == "1");
    ASSERT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestUsbReadOnlyPlugin002
 * @tc.desc: Test UsbReadOnlyPlugin::OnSetPolicy function to set usb read write.
 * @tc.type: FUNC
 */
HWTEST_F(UsbReadOnlyPluginTest, TestUsbReadOnlyPlugin002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    // want to set usb read write
    data.WriteInt32(0);
    std::shared_ptr<IPlugin> plugin = UsbReadOnlyPlugin::GetPlugin();
    // origin policy is allowed to read write
    HandlePolicyData handlePolicyData{"0", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USB_READ_ONLY);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    // current policy is read only
    ASSERT_TRUE(handlePolicyData.policyData == "0");
    ASSERT_FALSE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestUsbReadOnlyPlugin003
 * @tc.desc: Test UsbReadOnlyPlugin::OnSetPolicy function to set usb disabled.
 * @tc.type: FUNC
 */
HWTEST_F(UsbReadOnlyPluginTest, TestUsbReadOnlyPlugin003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    // want to set usb disabled
    data.WriteInt32(2);
    std::shared_ptr<IPlugin> plugin = UsbReadOnlyPlugin::GetPlugin();
    // origin policy is allowed to read write
    HandlePolicyData handlePolicyData{"0", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::USB_READ_ONLY);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    // current policy is read only
    ASSERT_TRUE(handlePolicyData.policyData == "2");
    ASSERT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestUsbReadOnlyPlugin004
 * @tc.desc: Test UsbReadOnlyPlugin::OnGetPolicy function when policy is read write.
 * @tc.type: FUNC
 */
HWTEST_F(UsbReadOnlyPluginTest, TestUsbReadOnlyPlugin004, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::shared_ptr<IPlugin> plugin = UsbReadOnlyPlugin::GetPlugin();
    std::string policyData{"0"};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == 0);
}

/**
 * @tc.name: TestUsbReadOnlyPlugin005
 * @tc.desc: Test UsbReadOnlyPlugin::OnGetPolicy function when policy is read only.
 * @tc.type: FUNC
 */
HWTEST_F(UsbReadOnlyPluginTest, TestUsbReadOnlyPlugin005, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::shared_ptr<IPlugin> plugin = UsbReadOnlyPlugin::GetPlugin();
    std::string policyData{"1"};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == 1);
}

/**
 * @tc.name: TestUsbReadOnlyPlugin006
 * @tc.desc: Test UsbReadOnlyPlugin::OnGetPolicy function when policy is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(UsbReadOnlyPluginTest, TestUsbReadOnlyPlugin006, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::shared_ptr<IPlugin> plugin = UsbReadOnlyPlugin::GetPlugin();
    std::string policyData{"2"};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == 2);
}

/**
 * @tc.name: TestUsbReadOnlyPlugin007
 * @tc.desc: Test UsbReadOnlyPlugin::OnGetPolicy function when policy is empty.
 * @tc.type: FUNC
 */
HWTEST_F(UsbReadOnlyPluginTest, TestUsbReadOnlyPlugin007, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::shared_ptr<IPlugin> plugin = UsbReadOnlyPlugin::GetPlugin();
    std::string policyData{""};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == 0);
}

/**
 * @tc.name: TestUsbReadOnlyPlugin008
 * @tc.desc: Test UsbReadOnlyPlugin::OnAdminRemove function when policy is read write.
 * @tc.type: FUNC
 */
HWTEST_F(UsbReadOnlyPluginTest, TestUsbReadOnlyPlugin008, TestSize.Level1)
{
    UsbReadOnlyPlugin plugin;
    std::string adminName{"testAdminName"};
    int32_t policyData = 0;
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestUsbReadOnlyPlugin009
 * @tc.desc: Test UsbReadOnlyPlugin::OnAdminRemove function when policy is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(UsbReadOnlyPluginTest, TestUsbReadOnlyPlugin009, TestSize.Level1)
{
    UsbReadOnlyPlugin plugin;
    std::string adminName{"testAdminName"};
    int32_t policyData = 2;
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS