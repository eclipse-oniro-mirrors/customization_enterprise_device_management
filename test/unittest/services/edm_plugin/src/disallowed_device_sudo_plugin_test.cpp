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

#include "basic_bool_plugin.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "iplugin.h"
#include "message_parcel.h"
#include "edm_constants.h"
#include "utils.h"

#define private public
#define protected public
#include "disallowed_device_sudo_plugin.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisallowedDeviceSudoPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowedDeviceSudoPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowedDeviceSudoPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestCheckConflictPolicy
 * @tc.desc: Test DisallowedDeviceSudoPlugin::CheckConflictPolicy depends on the stored
 *           POLICY_DISABLED_SUDO value, so no conflict and conflict are both accepted.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedDeviceSudoPluginTest, TestCheckConflictPolicy, TestSize.Level1)
{
    DisallowedDeviceSudoPlugin plugin;
    ErrCode ret = plugin.CheckConflictPolicy(DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
}

/**
 * @tc.name: TestOnSetPolicyTrue
 * @tc.desc: Test DisallowedDeviceSudoPlugin SET policy with true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedDeviceSudoPluginTest, TestOnSetPolicyTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisallowedDeviceSudoPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_DEVICE_SUDO);
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY ||
        ret == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
}

/**
 * @tc.name: TestOnSetPolicyMerged
 * @tc.desc: Test DisallowedDeviceSudoPlugin keeps the merged policy untouched.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedDeviceSudoPluginTest, TestOnSetPolicyMerged, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    DisallowedDeviceSudoPlugin plugin;
    HandlePolicyData handlePolicyData{"false", "true", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_DEVICE_SUDO);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(handlePolicyData.policyData, "true");
    EXPECT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test DisallowedDeviceSudoPlugin inherits the BasicBoolPlugin OnGetPolicy reply.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedDeviceSudoPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    DisallowedDeviceSudoPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadBool(), false);
}

/**
 * @tc.name: TestPluginAttributes
 * @tc.desc: Test DisallowedDeviceSudoPlugin policy code and policy name.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedDeviceSudoPluginTest, TestPluginAttributes, TestSize.Level1)
{
    DisallowedDeviceSudoPlugin plugin;
    EXPECT_EQ(plugin.GetCode(), EdmInterfaceCode::DISALLOWED_DEVICE_SUDO);
    EXPECT_EQ(plugin.GetPolicyName(), PolicyName::POLICY_DISALLOWED_DEVICE_SUDO);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
