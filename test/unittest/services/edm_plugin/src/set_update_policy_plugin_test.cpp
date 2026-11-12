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
#include "iplugin.h"
#include "message_parcel.h"
#include "edm_constants.h"
#include "set_update_policy_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class SetUpdatePolicyPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SetUpdatePolicyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SetUpdatePolicyPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestOnSetPolicy
 * @tc.desc: Test SetUpdatePolicyPlugin::OnSetPolicy returns unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(SetUpdatePolicyPluginTest, TestOnSetPolicy, TestSize.Level1)
{
    SetUpdatePolicyPlugin plugin;
    UpdatePolicy policy;
    ErrCode ret = plugin.OnSetPolicy(policy);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test SetUpdatePolicyPlugin::OnGetPolicy returns unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(SetUpdatePolicyPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    SetUpdatePolicyPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestPluginAttributes
 * @tc.desc: Test SetUpdatePolicyPlugin policy code and policy name.
 * @tc.type: FUNC
 */
HWTEST_F(SetUpdatePolicyPluginTest, TestPluginAttributes, TestSize.Level1)
{
    auto plugin = SetUpdatePolicyPlugin::GetPlugin();
    ASSERT_NE(plugin, nullptr);
    EXPECT_EQ(plugin->GetCode(), EdmInterfaceCode::SET_OTA_UPDATE_POLICY);
    EXPECT_EQ(plugin->GetPolicyName(), PolicyName::POLICY_SET_UPDATE_POLICY);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
