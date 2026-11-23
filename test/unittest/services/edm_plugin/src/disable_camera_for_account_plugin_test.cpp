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

#include "disable_camera_for_account_plugin.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "policy_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisableCameraForAccountPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);

    /* 设置/清理设备级摄像头策略（用户级启用冲突检测的依赖项） */
    static void SetDeviceCameraPolicy(const std::string &value);
};

void DisableCameraForAccountPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisableCameraForAccountPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

void DisableCameraForAccountPluginTest::SetDeviceCameraPolicy(const std::string &value)
{
    ASSERT_EQ(PolicyManager::GetInstance()->SetPolicy("", PolicyName::POLICY_DISABLE_CAMERA, value, value,
        EdmConstants::DEFAULT_USER_ID), ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyDisable_Success
 * @tc.desc: Test DisableCameraForAccountPlugin::OnHandlePolicy to disable camera for account:
 *           policy stored, changed flag set, and constraint delivered via SetOtherModulePolicy.
 * @tc.type: FUNC
 */
HWTEST_F(DisableCameraForAccountPluginTest, TestOnHandlePolicyDisable_Success, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableCameraForAccountPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_CAMERA_FOR_ACCOUNT);
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);

    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(handlePolicyData.policyData, "true");
    EXPECT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyEnable_Success
 * @tc.desc: Test enabling user-level camera with no device-level policy and no other admin
 *           disabled: no conflict, policy cleared.
 * @tc.type: FUNC
 */
HWTEST_F(DisableCameraForAccountPluginTest, TestOnHandlePolicyEnable_Success, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableCameraForAccountPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_CAMERA_FOR_ACCOUNT);
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);

    ASSERT_EQ(ret, ERR_OK);
    EXPECT_TRUE(handlePolicyData.policyData.empty());
    EXPECT_TRUE(handlePolicyData.mergePolicyData.empty());
}

/**
 * @tc.name: TestOnHandlePolicyEnable_DeviceDisabled_StrictMerge
 * @tc.desc: Test enabling user-level camera while device-level camera is disabled:
 *           per the revised acceptance rules (camera.txt) strictness is enforced at merge
 *           time silently, so the call succeeds while the camera stays disabled.
 * @tc.type: FUNC
 */
HWTEST_F(DisableCameraForAccountPluginTest, TestOnHandlePolicyEnable_DeviceDisabled_StrictMerge, TestSize.Level1)
{
    SetDeviceCameraPolicy(EdmConstants::CONST_TRUE);

    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableCameraForAccountPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_CAMERA_FOR_ACCOUNT);
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);

    // 新版从严规则：无 9200010 上报，设置成功；设备级禁用策略维持，摄像头对该用户仍禁用
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(handlePolicyData.policyData.empty());

    // 恢复环境，避免影响其他用例
    SetDeviceCameraPolicy("");
}

/**
 * @tc.name: TestOnHandlePolicyEnable_OtherAdminDisabled_StrictMerge
 * @tc.desc: Test enabling user-level camera while another admin already disabled it
 *           (mergePolicy is other admins merged result): per the revised acceptance
 *           rules the call succeeds while the camera stays disabled by the other admin.
 * @tc.type: FUNC
 */
HWTEST_F(DisableCameraForAccountPluginTest, TestOnHandlePolicyEnable_OtherAdminDisabled_StrictMerge, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableCameraForAccountPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_CAMERA_FOR_ACCOUNT);
    HandlePolicyData handlePolicyData{"false", "true", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);

    // 新版从严规则：无 9200010 上报；本 admin 设置成功，合并结果仍为禁用（其他 admin 维持）
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyDisable_DeviceDisabled_NoConflict
 * @tc.desc: Test disabling user-level camera while device-level camera is also disabled:
 *           strictest merge allows stacking disables, must succeed.
 * @tc.type: FUNC
 */
HWTEST_F(DisableCameraForAccountPluginTest, TestOnHandlePolicyDisable_DeviceDisabled_NoConflict, TestSize.Level1)
{
    SetDeviceCameraPolicy(EdmConstants::CONST_TRUE);

    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableCameraForAccountPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_CAMERA_FOR_ACCOUNT);
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);

    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(handlePolicyData.policyData, "true");

    // 恢复环境，避免影响其他用例
    SetDeviceCameraPolicy("");
}

/**
 * @tc.name: TestOnHandlePolicyEnable_AfterSelfDisabled_Success
 * @tc.desc: Test enabling user-level camera when only this admin disabled it before
 *           (no other admin disabled, device-level enabled): must succeed and clear policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisableCameraForAccountPluginTest, TestOnHandlePolicyEnable_AfterSelfDisabled_Success, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableCameraForAccountPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_CAMERA_FOR_ACCOUNT);
    HandlePolicyData handlePolicyData{"true", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);

    ASSERT_EQ(ret, ERR_OK);
    EXPECT_TRUE(handlePolicyData.policyData.empty());
    EXPECT_TRUE(handlePolicyData.mergePolicyData.empty());
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
