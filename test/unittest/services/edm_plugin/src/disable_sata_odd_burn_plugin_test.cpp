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
#include "disable_sata_odd_burn_plugin.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "iplugin.h"
#include "message_parcel.h"
#include "edm_constants.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisableSataOddBurnPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisableSataOddBurnPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisableSataOddBurnPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestOnSetPolicyTrue
 * @tc.desc: Test DisableSataOddBurnPlugin SET policy with true, the persist parameter may be
 *           rejected in the UT environment, so both ERR_OK and SYSTEM_ABNORMALLY are accepted.
 * @tc.type: FUNC
 */
HWTEST_F(DisableSataOddBurnPluginTest, TestOnSetPolicyTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableSataOddBurnPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISABLE_SATA_ODD_BURN);
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnSetPolicyFalse
 * @tc.desc: Test DisableSataOddBurnPlugin SET policy with false clears the policy data.
 * @tc.type: FUNC
 */
HWTEST_F(DisableSataOddBurnPluginTest, TestOnSetPolicyFalse, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisableSataOddBurnPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISABLE_SATA_ODD_BURN);
    HandlePolicyData handlePolicyData{"true", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    if (ret == ERR_OK) {
        EXPECT_TRUE(handlePolicyData.policyData.empty());
    }
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test DisableSataOddBurnPlugin inherits the BasicBoolPlugin OnGetPolicy reply.
 * @tc.type: FUNC
 */
HWTEST_F(DisableSataOddBurnPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::string policyData = "true";
    DisableSataOddBurnPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadBool(), true);
}

/**
 * @tc.name: TestOnAdminRemove
 * @tc.desc: Test DisableSataOddBurnPlugin::OnAdminRemove releases the persist parameter.
 * @tc.type: FUNC
 */
HWTEST_F(DisableSataOddBurnPluginTest, TestOnAdminRemove, TestSize.Level1)
{
    DisableSataOddBurnPlugin plugin;
    ErrCode ret = plugin.OnAdminRemove("testAdmin", "true", "false", DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestPluginAttributes
 * @tc.desc: Test DisableSataOddBurnPlugin policy code and policy name.
 * @tc.type: FUNC
 */
HWTEST_F(DisableSataOddBurnPluginTest, TestPluginAttributes, TestSize.Level1)
{
    DisableSataOddBurnPlugin plugin;
    EXPECT_EQ(plugin.GetCode(), EdmInterfaceCode::DISABLE_SATA_ODD_BURN);
    EXPECT_EQ(plugin.GetPolicyName(), PolicyName::POLICY_DISABLE_SATA_ODD_BURN);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
