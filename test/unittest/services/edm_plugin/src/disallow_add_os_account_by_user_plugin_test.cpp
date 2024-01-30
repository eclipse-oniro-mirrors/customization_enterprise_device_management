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

#include "disallow_add_os_account_by_user_plugin.h"

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string STR_DEFAULT_USER_ID = "100";
const std::string STR_UNAVAIL_USER_ID = "9876";
const int32_t UNAVAIL_USER_ID = 9876;

class DisallowAddOsAccountByUserPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowAddOsAccountByUserPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowAddOsAccountByUserPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicyEmpty
 * @tc.desc: Test DisallowAddOsAccountByUserPlugin::OnSetPolicy function when policy is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAddOsAccountByUserPluginTest, TestOnSetPolicyEmpty, TestSize.Level1)
{
    DisallowAddOsAccountByUserPlugin plugin;
    std::map<std::string, std::string> policies;
    ErrCode ret = plugin.OnSetPolicy(policies);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyUserIdEmpty
 * @tc.desc: Test DisallowAddOsAccountByUserPlugin::OnSetPolicy function when user id value is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAddOsAccountByUserPluginTest, TestOnSetPolicyUserIdEmpty, TestSize.Level1)
{
    DisallowAddOsAccountByUserPlugin plugin;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair("", "true"));
    ErrCode ret = plugin.OnSetPolicy(policies);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnSetPolicyUserIdUnavailable
 * @tc.desc: Test DisallowAddOsAccountByUserPlugin::OnSetPolicy function when user id value is unavailable.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAddOsAccountByUserPluginTest, TestOnSetPolicyUserIdUnavailable, TestSize.Level1)
{
    DisallowAddOsAccountByUserPlugin plugin;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair(STR_UNAVAIL_USER_ID, "true"));
    ErrCode ret = plugin.OnSetPolicy(policies);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnSetPolicyTrue
 * @tc.desc: Test DisallowAddOsAccountByUserPlugin::OnSetPolicy function when value is true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAddOsAccountByUserPluginTest, TestOnSetPolicyTrue, TestSize.Level1)
{
    DisallowAddOsAccountByUserPlugin plugin;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair(STR_DEFAULT_USER_ID, "true"));
    ErrCode ret = plugin.OnSetPolicy(policies);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyFalse
 * @tc.desc: Test DisallowAddOsAccountByUserPlugin::OnSetPolicy function when value is false.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAddOsAccountByUserPluginTest, TestOnSetPolicyFalse, TestSize.Level1)
{
    DisallowAddOsAccountByUserPlugin plugin;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair(STR_DEFAULT_USER_ID, "false"));
    ErrCode ret = plugin.OnSetPolicy(policies);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test DisallowAddOsAccountByUserPlugin::OnGetPolicy function when policy is read write.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAddOsAccountByUserPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInt32(DEFAULT_USER_ID);
    MessageParcel reply;
    std::shared_ptr<IPlugin> plugin = DisallowAddOsAccountByUserPlugin::GetPlugin();
    std::string policyData{""};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_FALSE(reply.ReadBool());
}

/**
 * @tc.name: TestOnGetPolicyUserIdUnavailable
 * @tc.desc: Test DisallowAddOsAccountByUserPlugin::OnGetPolicy function when user id is unavailable.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAddOsAccountByUserPluginTest, TestOnGetPolicyUserIdUnavailable, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInt32(UNAVAIL_USER_ID);
    MessageParcel reply;
    std::shared_ptr<IPlugin> plugin = DisallowAddOsAccountByUserPlugin::GetPlugin();
    std::string policyData{""};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::PARAM_ERROR);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS