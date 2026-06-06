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

#define protected public
#define private public
#include "disable_usb_plugin.h"
#undef private
#undef protected

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "ipolicy_manager.h"
#include "policy_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisableUsbPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisableUsbPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisableUsbPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicyTrue
 * @tc.desc: Test DisableUsbPlugin::OnSetPolicy function to set true.
 * @tc.type: FUNC
 */
HWTEST_F(DisableUsbPluginTest, TestOnSetPolicyTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableUsbPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISABLE_USB);
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestOnSetPolicyFalse
 * @tc.desc: Test DisableUsbPlugin::OnSetPolicy function to set false.
 * @tc.type: FUNC
 */
HWTEST_F(DisableUsbPluginTest, TestOnSetPolicyFalse, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableUsbPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISABLE_USB);
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveTrue
 * @tc.desc: Test DisableUsbPlugin::OnAdminRemove function when policy is true.
 * @tc.type: FUNC
 */
HWTEST_F(DisableUsbPluginTest, TestOnAdminRemoveTrue, TestSize.Level1)
{
    DisableUsbPlugin plugin;
    std::string adminName{"testAdminName"};
    bool policyData = true;
    bool mergeData = false;
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveFalse
 * @tc.desc: Test DisableUsbPlugin::OnAdminRemove function when policy is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(DisableUsbPluginTest, TestOnAdminRemoveFalse, TestSize.Level1)
{
    DisableUsbPlugin plugin;
    std::string adminName{"testAdminName"};
    bool policyData = false;
    bool mergeData = false;
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: HasConflictPolicy_DisallowedPermissiveUsbDeviceNotEmpty_HasConflict
 * @tc.desc: Test DisableUsbPlugin::HasConflictPolicy when disallowed permissive USB device policy is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisableUsbPluginTest, HasConflictPolicy_DisallowedPermissiveUsbDeviceNotEmpty_HasConflict, TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    const std::string policyValue = "[{\"baseClass\":8,\"subClass\":6,\"protocol\":50}]";

    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(testAdminName,
        PolicyName::POLICY_DISALLOWED_PERMISSIVE_USB_DEVICES, policyValue, policyValue, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    DisableUsbPlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    ErrCode clearRes = policyManager->SetPolicy(testAdminName,
        PolicyName::POLICY_DISALLOWED_PERMISSIVE_USB_DEVICES, "", "", DEFAULT_USER_ID);
    ASSERT_TRUE(clearRes == ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS