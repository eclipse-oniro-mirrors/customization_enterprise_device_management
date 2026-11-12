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

#define protected public
#define private public
#include "usb_intercept_enable_plugin.h"
#undef private
#undef protected

#include <gtest/gtest.h>

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "ipolicy_manager.h"
#include "parameters.h"
#include "policy_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string PERSIST_EDM_USB_INTERCEPT_ENABLE = "persist.edm.usb.intercept_enable";
const std::string TEST_ADMIN_NAME = "com.edm.test.demo";

class UsbInterceptEnablePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
    void AssertConflictWithPolicy(const std::string &policyName, const std::string &policyValue);
    void AssertNoConflictWithPolicy(const std::string &policyName, const std::string &policyValue);
};

void UsbInterceptEnablePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void UsbInterceptEnablePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    OHOS::system::SetParameter(PERSIST_EDM_USB_INTERCEPT_ENABLE, "false");
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

void UsbInterceptEnablePluginTest::AssertConflictWithPolicy(const std::string &policyName,
    const std::string &policyValue)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();
    ErrCode res = policyManager->SetPolicy(TEST_ADMIN_NAME, policyName, policyValue, policyValue, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    UsbInterceptEnablePlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
    policyManager->SetPolicy(TEST_ADMIN_NAME, policyName, "", "", DEFAULT_USER_ID);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

void UsbInterceptEnablePluginTest::AssertNoConflictWithPolicy(const std::string &policyName,
    const std::string &policyValue)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();
    ErrCode res = policyManager->SetPolicy(TEST_ADMIN_NAME, policyName, policyValue, policyValue, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);
    UsbInterceptEnablePlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    policyManager->SetPolicy(TEST_ADMIN_NAME, policyName, "", "", DEFAULT_USER_ID);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestOnHandlePolicyTrue
 * @tc.desc: Test UsbInterceptEnablePlugin::OnHandlePolicy set true then false.
 * @tc.type: FUNC
 */
HWTEST_F(UsbInterceptEnablePluginTest, TestOnHandlePolicyTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = std::make_shared<UsbInterceptEnablePlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE_NEW((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::USB_INTERCEPT_ENABLE);
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.isChanged);
    ASSERT_TRUE(handlePolicyData.policyData == EdmConstants::CONST_TRUE);
    std::string value = system::GetParameter(PERSIST_EDM_USB_INTERCEPT_ENABLE, "false");
    ASSERT_TRUE(value == EdmConstants::CONST_TRUE);

    MessageParcel dataFalse;
    dataFalse.WriteBool(false);
    HandlePolicyData handlePolicyDataFalse{EdmConstants::CONST_TRUE, "", false};
    ret = plugin->OnHandlePolicy(funcCode, dataFalse, reply, handlePolicyDataFalse, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    value = system::GetParameter(PERSIST_EDM_USB_INTERCEPT_ENABLE, "false");
    ASSERT_TRUE(value == EdmConstants::CONST_FALSE);
}

/**
 * @tc.name: TestOnGetPolicyTrue
 * @tc.desc: Test UsbInterceptEnablePlugin::OnGetPolicy when policy is true.
 * @tc.type: FUNC
 */
HWTEST_F(UsbInterceptEnablePluginTest, TestOnGetPolicyTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::shared_ptr<IPlugin> plugin = std::make_shared<UsbInterceptEnablePlugin>();
    std::string policyData = EdmConstants::CONST_TRUE;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadBool());
}

/**
 * @tc.name: TestCheckConflictPolicyNoConflict
 * @tc.desc: Test UsbInterceptEnablePlugin::CheckConflictPolicy when no conflict.
 * @tc.type: FUNC
 */
HWTEST_F(UsbInterceptEnablePluginTest, TestCheckConflictPolicyNoConflict, TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();
    UsbInterceptEnablePlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestCheckConflictPolicyDisableUsb
 * @tc.desc: Test CheckConflictPolicy when disable usb policy is true.
 * @tc.type: FUNC
 */
HWTEST_F(UsbInterceptEnablePluginTest, TestCheckConflictPolicyDisableUsb, TestSize.Level1)
{
    AssertConflictWithPolicy(PolicyName::POLICY_DISABLE_USB, EdmConstants::CONST_TRUE);
}

/**
 * @tc.name: TestCheckConflictPolicyDisallowUsbSerial
 * @tc.desc: Test CheckConflictPolicy when usb serial is disallowed.
 * @tc.type: FUNC
 */
HWTEST_F(UsbInterceptEnablePluginTest, TestCheckConflictPolicyDisallowUsbSerial, TestSize.Level1)
{
    AssertConflictWithPolicy(PolicyName::POLICY_DISALLOW_USB_SERIAL, EdmConstants::CONST_TRUE);
}

/**
 * @tc.name: TestCheckConflictPolicyUsbStorageDisabled
 * @tc.desc: Test CheckConflictPolicy when usb storage access policy is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(UsbInterceptEnablePluginTest, TestCheckConflictPolicyUsbStorageDisabled, TestSize.Level1)
{
    AssertConflictWithPolicy(PolicyName::POLICY_USB_READ_ONLY,
        std::to_string(EdmConstants::STORAGE_USB_POLICY_DISABLED));
}

/**
 * @tc.name: TestCheckConflictPolicyDisallowedUsbDevices
 * @tc.desc: Test CheckConflictPolicy when disallowed usb devices is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(UsbInterceptEnablePluginTest, TestCheckConflictPolicyDisallowedUsbDevices, TestSize.Level1)
{
    AssertConflictWithPolicy(PolicyName::POLICY_DISALLOWED_USB_DEVICES,
        "[{\"baseClass\":8,\"subClass\":6,\"protocol\":80,\"isInterfaceRestricted\":true}]");
}

/**
 * @tc.name: TestCheckConflictPolicyDisallowedPermissiveUsbDevices
 * @tc.desc: Test CheckConflictPolicy when disallowed permissive usb devices is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(UsbInterceptEnablePluginTest, TestCheckConflictPolicyDisallowedPermissiveUsbDevices, TestSize.Level1)
{
    AssertConflictWithPolicy(PolicyName::POLICY_DISALLOWED_PERMISSIVE_USB_DEVICES,
        "[{\"baseClass\":3,\"subClass\":1,\"protocol\":2,\"isInterfaceRestricted\":true}]");
}

/**
 * @tc.name: TestCheckConflictPolicyAllowedUsbDevices
 * @tc.desc: Test CheckConflictPolicy when allowed usb devices is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(UsbInterceptEnablePluginTest, TestCheckConflictPolicyAllowedUsbDevices, TestSize.Level1)
{
    AssertConflictWithPolicy(PolicyName::POLICY_ALLOWED_USB_DEVICES, "[{\"vendorId\":1,\"productId\":2}]");
}

/**
 * @tc.name: TestCheckConflictPolicyExternalStorageInterceptNoConflict
 * @tc.desc: Test CheckConflictPolicy allows external storage intercept coexistence.
 * @tc.type: FUNC
 */
HWTEST_F(UsbInterceptEnablePluginTest, TestCheckConflictPolicyExternalStorageInterceptNoConflict, TestSize.Level1)
{
    AssertNoConflictWithPolicy(PolicyName::POLICY_EXTERNAL_STORAGE_INTERCEPT_ENABLE, EdmConstants::CONST_TRUE);
}

/**
 * @tc.name: TestCheckConflictPolicyUsbReadOnlyNoConflict
 * @tc.desc: Test CheckConflictPolicy allows usb storage read-only coexistence.
 * @tc.type: FUNC
 */
HWTEST_F(UsbInterceptEnablePluginTest, TestCheckConflictPolicyUsbReadOnlyNoConflict, TestSize.Level1)
{
    AssertNoConflictWithPolicy(PolicyName::POLICY_USB_READ_ONLY,
        std::to_string(EdmConstants::STORAGE_USB_POLICY_READ_ONLY));
}

/**
 * @tc.name: TestCheckConflictPolicyDisallowedUsbStorageWriteNoConflict
 * @tc.desc: Test CheckConflictPolicy allows disallowed usb storage write coexistence.
 * @tc.type: FUNC
 */
HWTEST_F(UsbInterceptEnablePluginTest, TestCheckConflictPolicyDisallowedUsbStorageWriteNoConflict, TestSize.Level1)
{
    AssertNoConflictWithPolicy(PolicyName::POLICY_DISALLOWED_USB_STORAGE_DEVICE_WRITE, EdmConstants::CONST_TRUE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
