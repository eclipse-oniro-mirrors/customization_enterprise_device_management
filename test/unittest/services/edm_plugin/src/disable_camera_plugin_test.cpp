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

#include <gtest/gtest.h>

#define protected public
#include "disable_camera_plugin.h"
#undef protected
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "policy_manager.h"
#include "basic_bool_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisableCameraPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisableCameraPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisableCameraPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicyTrue
 * @tc.desc: Test DisableCameraPluginTest::OnSetPolicy function to set true.
 * @tc.type: FUNC
 */
HWTEST_F(DisableCameraPluginTest, TestOnSetPolicyTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableCameraPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISABLE_CAMERA);
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyFalse
 * @tc.desc: Test DisableCameraPluginTest::OnSetPolicy function to set false.
 * @tc.type: FUNC
 */
HWTEST_F(DisableCameraPluginTest, TestOnSetPolicyFalse, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableCameraPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISABLE_CAMERA);
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveTrue
 * @tc.desc: Test DisableCameraPluginTest::OnAdminRemove function when policy is true.
 * @tc.type: FUNC
 */
HWTEST_F(DisableCameraPluginTest, TestOnAdminRemoveTrue, TestSize.Level1)
{
    DisableCameraPlugin plugin;
    std::string adminName{"testAdminName"};
    bool policyData = true;
    bool mergeData = false;
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveFalse
 * @tc.desc: Test DisableCameraPluginTest::OnAdminRemove function when policy is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(DisableCameraPluginTest, TestOnAdminRemoveFalse, TestSize.Level1)
{
    DisableCameraPlugin plugin;
    std::string adminName{"testAdminName"};
    bool policyData = false;
    bool mergeData = false;
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyEnable_UserDisabled_StrictMerge
 * @tc.desc: Test enabling device-level camera while some account has user-level CAMERA
 *           disabled: per the revised acceptance rules (camera.txt) the call succeeds and
 *           the user-level disable policy is kept, so that user camera stays disabled.
 * @tc.type: FUNC
 */
HWTEST_F(DisableCameraPluginTest, TestOnSetPolicyEnable_UserDisabled_StrictMerge, TestSize.Level1)
{
    // 预置用户级摄像头禁用策略（DEFAULT_USER_ID 账号）。
    // 必须用 PolicyManager::GetInstance()：它会把真实 PolicyManager 装进 IPolicyManager 单例，
    // 否则若前序用例把单例置空，IPolicyManager::GetInstance() 退化为基类空实现，SetPolicy 假成功、预置不落库
    auto policyManager = PolicyManager::GetInstance();
    ASSERT_EQ(policyManager->SetPolicy("", PolicyName::POLICY_DISABLED_CAMERA_FOR_ACCOUNT,
        EdmConstants::CONST_TRUE, EdmConstants::CONST_TRUE, DEFAULT_USER_ID), ERR_OK);

    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableCameraPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISABLE_CAMERA);
    HandlePolicyData handlePolicyData{"false", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);

    // 新版从严规则：无 9200010 上报；设备级启用成功，用户级禁用策略保留（该用户摄像头仍禁用）
    EXPECT_EQ(ret, ERR_OK);
    std::string userPolicy;
    policyManager->GetPolicy("", PolicyName::POLICY_DISABLED_CAMERA_FOR_ACCOUNT, userPolicy, DEFAULT_USER_ID);
    EXPECT_EQ(userPolicy, EdmConstants::CONST_TRUE);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS