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
#include "iplugin_event_subscribe_manager.h"
#include "key_code.h"
#include "message_parcel.h"
#include "edm_constants.h"
#include "utils.h"

#define private public
#define protected public
#include "set_key_code_plugin.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class SetKeyCodePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SetKeyCodePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SetKeyCodePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestOnHandlePolicy
 * @tc.desc: Test SetKeyCodePlugin::OnHandlePolicy returns unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(SetKeyCodePluginTest, TestOnHandlePolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(1);
    SetKeyCodePlugin plugin;
    HandlePolicyData handlePolicyData{"", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_KEY_CODE_POLICYS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test SetKeyCodePlugin::OnGetPolicy returns unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(SetKeyCodePluginTest, TestOnGetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    SetKeyCodePlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestOnAdminRemove
 * @tc.desc: Test SetKeyCodePlugin::OnAdminRemove returns unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(SetKeyCodePluginTest, TestOnAdminRemove, TestSize.Level1)
{
    SetKeyCodePlugin plugin;
    ErrCode ret = plugin.OnAdminRemove("testAdmin", "{}", "{}", DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestSetOtherModulePolicy
 * @tc.desc: Test SetKeyCodePlugin policy handlers return unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(SetKeyCodePluginTest, TestSetOtherModulePolicy, TestSize.Level1)
{
    SetKeyCodePlugin plugin;
    std::vector<KeyCustomization> keyCustomizations;
    std::vector<KeyCustomization> currentData;
    std::vector<KeyCustomization> mergeData;
    ErrCode ret = plugin.OnSetPolicy(keyCustomizations, currentData, mergeData);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);

    std::vector<int> keyCodes;
    ret = plugin.OnRemovePolicy(keyCodes, currentData, mergeData);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);

    ret = plugin.SetOtherModulePolicy(keyCustomizations);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestOnOtherServiceStartForAdmin
 * @tc.desc: Test SetKeyCodePlugin::OnOtherServiceStartForAdmin is a no-op.
 * @tc.type: FUNC
 */
HWTEST_F(SetKeyCodePluginTest, TestOnOtherServiceStartForAdmin, TestSize.Level1)
{
    SetKeyCodePlugin plugin;
    plugin.OnOtherServiceStartForAdmin("testAdmin", DEFAULT_USER_ID);
    EXPECT_EQ(plugin.GetCode(), EdmInterfaceCode::SET_KEY_CODE_POLICYS);
}

/**
 * @tc.name: TestPluginAttributes
 * @tc.desc: Test SetKeyCodePlugin policy code and policy name.
 * @tc.type: FUNC
 */
HWTEST_F(SetKeyCodePluginTest, TestPluginAttributes, TestSize.Level1)
{
    SetKeyCodePlugin plugin;
    EXPECT_EQ(plugin.GetPolicyName(), PolicyName::POLICY_SET_KEY_CODE);
}

/**
 * @tc.name: TestExtendedKeyCodeValues
 * @tc.desc: Test extended KeyCode enum values for PC keyboard keys.
 * @tc.type: FUNC
 */
HWTEST_F(SetKeyCodePluginTest, TestExtendedKeyCodeValues, TestSize.Level1)
{
    EXPECT_EQ(static_cast<int32_t>(KeyCode::FN), 6);
    EXPECT_EQ(static_cast<int32_t>(KeyCode::DPAD_UP), 7);
    EXPECT_EQ(static_cast<int32_t>(KeyCode::DPAD_DOWN), 8);
    EXPECT_EQ(static_cast<int32_t>(KeyCode::DPAD_LEFT), 9);
    EXPECT_EQ(static_cast<int32_t>(KeyCode::DPAD_RIGHT), 10);
    EXPECT_EQ(static_cast<int32_t>(KeyCode::DPAD_CENTER), 11);
    EXPECT_EQ(static_cast<int32_t>(KeyCode::BRIGHTNESS_UP), 12);
    EXPECT_EQ(static_cast<int32_t>(KeyCode::BRIGHTNESS_DOWN), 13);
    EXPECT_EQ(static_cast<int32_t>(KeyCode::ESCAPE), 14);
    EXPECT_EQ(static_cast<int32_t>(KeyCode::F1), 15);
    EXPECT_EQ(static_cast<int32_t>(KeyCode::F12), 26);
}

/**
 * @tc.name: TestOnSetPolicyWithExtendedKeyCode
 * @tc.desc: Test OnSetPolicy with extended KeyCode still returns unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(SetKeyCodePluginTest, TestOnSetPolicyWithExtendedKeyCode, TestSize.Level1)
{
    SetKeyCodePlugin plugin;
    std::vector<KeyCustomization> keyCustomizations;
    KeyCustomization item;
    item.keyCode = static_cast<int32_t>(KeyCode::F1);
    item.keyPolicy = static_cast<int32_t>(KeyPolicy::INTERCEPTION);
    keyCustomizations.push_back(item);
    item.keyCode = static_cast<int32_t>(KeyCode::ESCAPE);
    item.keyPolicy = static_cast<int32_t>(KeyPolicy::CUSTOM);
    keyCustomizations.push_back(item);

    std::vector<KeyCustomization> currentData;
    std::vector<KeyCustomization> mergeData;
    ErrCode ret = plugin.OnSetPolicy(keyCustomizations, currentData, mergeData);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestOnRemovePolicyWithExtendedKeyCode
 * @tc.desc: Test OnRemovePolicy with extended KeyCode still returns unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(SetKeyCodePluginTest, TestOnRemovePolicyWithExtendedKeyCode, TestSize.Level1)
{
    SetKeyCodePlugin plugin;
    std::vector<int> keyCodes = {
        static_cast<int>(KeyCode::FN),
        static_cast<int>(KeyCode::F12),
        static_cast<int>(KeyCode::BRIGHTNESS_UP),
    };
    std::vector<KeyCustomization> currentData;
    std::vector<KeyCustomization> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(keyCodes, currentData, mergeData);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
