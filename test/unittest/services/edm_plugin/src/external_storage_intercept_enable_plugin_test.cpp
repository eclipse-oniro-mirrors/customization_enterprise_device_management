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
#include "external_storage_intercept_enable_plugin.h"
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
const std::string PERSIST_EDM_EXTERNAL_STORAGE_MOUNT_INTERCEPT = "persist.edm.enable_external_storage_mount_intercept";
class ExternalStorageInterceptEnablePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void ExternalStorageInterceptEnablePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ExternalStorageInterceptEnablePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    OHOS::system::SetParameter(PERSIST_EDM_EXTERNAL_STORAGE_MOUNT_INTERCEPT, "false");
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyTrue
 * @tc.desc: Test ExternalStorageInterceptEnablePlugin::OnHandlePolicy function to set true.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageInterceptEnablePluginTest, TestOnHandlePolicyTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = std::make_shared<ExternalStorageInterceptEnablePlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE_NEW((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::EXTERNAL_STORAGE_INTERCEPT_ENABLE);
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.isChanged);
    ASSERT_TRUE(handlePolicyData.policyData == EdmConstants::CONST_TRUE);
    std::string value = system::GetParameter(PERSIST_EDM_EXTERNAL_STORAGE_MOUNT_INTERCEPT, "false");
    ASSERT_TRUE(value == EdmConstants::CONST_TRUE);

    MessageParcel dataFalse;
    dataFalse.WriteBool(false);
    HandlePolicyData handlePolicyDataFalse{EdmConstants::CONST_TRUE, "", false};
    ret = plugin->OnHandlePolicy(funcCode, dataFalse, reply, handlePolicyDataFalse, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    value = system::GetParameter(PERSIST_EDM_EXTERNAL_STORAGE_MOUNT_INTERCEPT, "false");
    ASSERT_TRUE(value == EdmConstants::CONST_FALSE);
}

/**
 * @tc.name: TestOnHandlePolicyFalseNoChange
 * @tc.desc: Test ExternalStorageInterceptEnablePlugin::OnHandlePolicy function when policy is already false.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageInterceptEnablePluginTest, TestOnHandlePolicyFalseNoChange, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = std::make_shared<ExternalStorageInterceptEnablePlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE_NEW((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::EXTERNAL_STORAGE_INTERCEPT_ENABLE);
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestOnGetPolicyTrue
 * @tc.desc: Test ExternalStorageInterceptEnablePlugin::OnGetPolicy function when policy is true.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageInterceptEnablePluginTest, TestOnGetPolicyTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::shared_ptr<IPlugin> plugin = std::make_shared<ExternalStorageInterceptEnablePlugin>();
    std::string policyData = EdmConstants::CONST_TRUE;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadBool());
}

/**
 * @tc.name: TestOnGetPolicyFalse
 * @tc.desc: Test ExternalStorageInterceptEnablePlugin::OnGetPolicy function when policy is false.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageInterceptEnablePluginTest, TestOnGetPolicyFalse, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::shared_ptr<IPlugin> plugin = std::make_shared<ExternalStorageInterceptEnablePlugin>();
    std::string policyData = "";
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_FALSE(reply.ReadBool());
}

/**
 * @tc.name: TestCheckConflictPolicyNoConflict
 * @tc.desc: Test ExternalStorageInterceptEnablePlugin::CheckConflictPolicy when no conflict.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageInterceptEnablePluginTest, TestCheckConflictPolicyNoConflict, TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ExternalStorageInterceptEnablePlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestCheckConflictPolicyDisableUsb
 * @tc.desc: Test CheckConflictPolicy when disable usb policy is true.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageInterceptEnablePluginTest, TestCheckConflictPolicyDisableUsb, TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(testAdminName, PolicyName::POLICY_DISABLE_USB,
        EdmConstants::CONST_TRUE, EdmConstants::CONST_TRUE, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    ExternalStorageInterceptEnablePlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    policyManager->SetPolicy(testAdminName, PolicyName::POLICY_DISABLE_USB, "", "", DEFAULT_USER_ID);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestCheckConflictPolicyAllowedUsbDevices
 * @tc.desc: Test CheckConflictPolicy when allowed usb devices is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageInterceptEnablePluginTest, TestCheckConflictPolicyAllowedUsbDevices, TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(testAdminName, PolicyName::POLICY_ALLOWED_USB_DEVICES,
        "[{\"vendorId\":1,\"productId\":2}]", "[{\"vendorId\":1,\"productId\":2}]", DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    ExternalStorageInterceptEnablePlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    policyManager->SetPolicy(testAdminName, PolicyName::POLICY_ALLOWED_USB_DEVICES, "", "", DEFAULT_USER_ID);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestCheckConflictPolicyDisallowedUsbDevices
 * @tc.desc: Test CheckConflictPolicy when disallowed usb devices is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageInterceptEnablePluginTest, TestCheckConflictPolicyDisallowedUsbDevices, TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(testAdminName, PolicyName::POLICY_DISALLOWED_USB_DEVICES,
        "[{\"baseClass\":3}]", "[{\"baseClass\":3}]", DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    ExternalStorageInterceptEnablePlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    policyManager->SetPolicy(testAdminName, PolicyName::POLICY_DISALLOWED_USB_DEVICES, "", "", DEFAULT_USER_ID);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestCheckConflictPolicyDisallowedPermissiveUsbDevices
 * @tc.desc: Test CheckConflictPolicy when disallowed permissive usb devices is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageInterceptEnablePluginTest, TestCheckConflictPolicyDisallowedPermissiveUsbDevices,
    TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(testAdminName, PolicyName::POLICY_DISALLOWED_PERMISSIVE_USB_DEVICES,
        "[{\"vendorId\":1,\"productId\":2}]", "[{\"vendorId\":1,\"productId\":2}]", DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    ExternalStorageInterceptEnablePlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    policyManager->SetPolicy(testAdminName, PolicyName::POLICY_DISALLOWED_PERMISSIVE_USB_DEVICES,
        "", "", DEFAULT_USER_ID);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestCheckConflictPolicyUsbReadOnlyDisabled
 * @tc.desc: Test CheckConflictPolicy when usb read only policy is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageInterceptEnablePluginTest, TestCheckConflictPolicyUsbReadOnlyDisabled, TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(testAdminName, PolicyName::POLICY_USB_READ_ONLY,
        std::to_string(EdmConstants::STORAGE_USB_POLICY_DISABLED),
        std::to_string(EdmConstants::STORAGE_USB_POLICY_DISABLED), DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    ExternalStorageInterceptEnablePlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    policyManager->SetPolicy(testAdminName, PolicyName::POLICY_USB_READ_ONLY, "", "", DEFAULT_USER_ID);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestCheckConflictPolicyUsbReadOnlyReadOnly
 * @tc.desc: Test CheckConflictPolicy when usb read only policy is read only.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageInterceptEnablePluginTest, TestCheckConflictPolicyUsbReadOnlyReadOnly, TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(testAdminName, PolicyName::POLICY_USB_READ_ONLY,
        std::to_string(EdmConstants::STORAGE_USB_POLICY_READ_ONLY),
        std::to_string(EdmConstants::STORAGE_USB_POLICY_READ_ONLY), DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    ExternalStorageInterceptEnablePlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    policyManager->SetPolicy(testAdminName, PolicyName::POLICY_USB_READ_ONLY, "", "", DEFAULT_USER_ID);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: TestCheckConflictPolicyDisallowedUsbStorageDeviceWrite
 * @tc.desc: Test CheckConflictPolicy when disallowed usb storage device write is true.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalStorageInterceptEnablePluginTest, TestCheckConflictPolicyDisallowedUsbStorageDeviceWrite,
    TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(testAdminName,
        PolicyName::POLICY_DISALLOWED_USB_STORAGE_DEVICE_WRITE,
        EdmConstants::CONST_TRUE, EdmConstants::CONST_TRUE, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    ExternalStorageInterceptEnablePlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    policyManager->SetPolicy(testAdminName, PolicyName::POLICY_DISALLOWED_USB_STORAGE_DEVICE_WRITE,
        "", "", DEFAULT_USER_ID);
    IPolicyManager::policyManagerInstance_ = nullptr;
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
