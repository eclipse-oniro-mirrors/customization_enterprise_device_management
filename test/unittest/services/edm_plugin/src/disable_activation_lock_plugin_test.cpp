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

#include "disable_activation_lock_plugin.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "message_parcel.h"
#include "edm_constants.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisableActivationLockPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisableActivationLockPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisableActivationLockPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestOnHandlePolicy
 * @tc.desc: Test DisableActivationLockPlugin::OnHandlePolicy returns unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(DisableActivationLockPluginTest, TestOnHandlePolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    DisableActivationLockPlugin plugin;
    HandlePolicyData handlePolicyData{"false", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISABLED_ACTIVATION_LOCK);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test DisableActivationLockPlugin::OnGetPolicy returns unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(DisableActivationLockPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    DisableActivationLockPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestOnAdminRemove
 * @tc.desc: Test DisableActivationLockPlugin::OnAdminRemove returns unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(DisableActivationLockPluginTest, TestOnAdminRemove, TestSize.Level1)
{
    DisableActivationLockPlugin plugin;
    ErrCode ret = plugin.OnAdminRemove("testAdmin", "true", "", DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestPluginAttributes
 * @tc.desc: Test DisableActivationLockPlugin policy code and policy name.
 * @tc.type: FUNC
 */
HWTEST_F(DisableActivationLockPluginTest, TestPluginAttributes, TestSize.Level1)
{
    DisableActivationLockPlugin plugin;
    EXPECT_EQ(plugin.GetCode(), EdmInterfaceCode::DISABLED_ACTIVATION_LOCK);
    EXPECT_EQ(plugin.GetPolicyName(), PolicyName::POLICY_DISABLED_ACTIVATION_LOCK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
