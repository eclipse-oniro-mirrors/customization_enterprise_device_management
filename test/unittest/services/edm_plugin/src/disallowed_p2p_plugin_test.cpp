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
#include "disallowed_p2p_plugin.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisallowedP2PPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowedP2PPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowedP2PPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestSetOtherModulePolicy
 * @tc.desc: Test DisallowedP2PPlugin::SetOtherModulePolicy, the WiFi P2P service is absent in
 *           the UT process, so both success and SYSTEM_ABNORMALLY are accepted.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedP2PPluginTest, TestSetOtherModulePolicy, TestSize.Level1)
{
    DisallowedP2PPlugin plugin;
    ErrCode ret = plugin.SetOtherModulePolicy(true, DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);

    ret = plugin.SetOtherModulePolicy(false, DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnSetPolicyTrue
 * @tc.desc: Test DisallowedP2PPlugin SET policy with true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedP2PPluginTest, TestOnSetPolicyTrue, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = std::make_shared<DisallowedP2PPlugin>();
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_P2P);
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test DisallowedP2PPlugin inherits the BasicBoolPlugin OnGetPolicy reply.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedP2PPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::string policyData = "true";
    DisallowedP2PPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadBool(), true);
}

/**
 * @tc.name: TestPluginAttributes
 * @tc.desc: Test DisallowedP2PPlugin policy code and policy name.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedP2PPluginTest, TestPluginAttributes, TestSize.Level1)
{
    DisallowedP2PPlugin plugin;
    EXPECT_EQ(plugin.GetCode(), EdmInterfaceCode::DISALLOWED_P2P);
    EXPECT_EQ(plugin.GetPolicyName(), PolicyName::POLICY_DISALLOWED_P2P);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
