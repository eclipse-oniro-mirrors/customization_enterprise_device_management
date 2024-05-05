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
#include "password_policy_plugin_test.h"
#include "password_policy_serializer.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_POLICY_DATA = "{\"complexityReg\":\"^(?=.*[a-zA-Z]).{1,9}$\", \"validityPeriod\": 2,"
    "\"additionalDescription\": \"testDescription\"}";
const std::string TEST_VALUE_COMPLEXITYREG = "^(?=.*[a-zA-Z]).{1,9}$";
const int TEST_VALUE_VALIDITY_PERIOD = 2;
const std::string TEST_VALUE_ADDITIONAL_DESCRIPTION = "testDescription";
void PasswordPolicyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void PasswordPolicyPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnGetPolicyEmpty
 * @tc.desc: Test PasswordPolicyPlugin::OnGetPolicy when policyData is empty
 * and policies is empty.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordPolicyPluginTest, TestOnGetPolicyEmpty, TestSize.Level1)
{
    PasswordPolicyPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, 0);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyData.empty());
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test PasswordPolicyPlugin::OnGetPolicy
 * and policies is empty.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordPolicyPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    PasswordPolicyPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    std::string policyData = TEST_POLICY_DATA;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, 0);
    ASSERT_TRUE(ret == ERR_OK);
    auto serializer_ = PasswordSerializer::GetInstance();
    PasswordPolicy policy;
    serializer_->Deserialize(policyData, policy);
    ASSERT_TRUE(policy.additionalDescription == TEST_VALUE_ADDITIONAL_DESCRIPTION);
    ASSERT_TRUE(policy.validityPeriod == TEST_VALUE_VALIDITY_PERIOD);
    ASSERT_TRUE(policy.complexityReg == TEST_VALUE_COMPLEXITYREG);
}

/**
 * @tc.name: TestOnSetPolicyEmpty
 * @tc.desc: Test PasswordPolicyPlugin::OnSetPolicy
 * @tc.type: FUNC
 */
HWTEST_F(PasswordPolicyPluginTest, TestOnSetPolicy, TestSize.Level1)
{
    PasswordPolicyPlugin plugin;
    PasswordPolicy policy;
    ErrCode ret = plugin.OnSetPolicy(policy);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS