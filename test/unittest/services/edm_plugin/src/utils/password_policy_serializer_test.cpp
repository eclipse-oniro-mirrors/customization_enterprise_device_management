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

#include "password_policy_serializer.h"
#include "password_policy_serializer_test.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_POLICY_DATA_ILEEGAL = "{\"complexityReg\":\"^(?=.*[a-zA-Z]).{1,9}$\", \"validityPeriod\": 2}";
const std::string TEST_POLICY_DATA = "{\"complexityReg\":\"^(?=.*[a-zA-Z]).{1,9}$\", \"validityPeriod\": 2,"
    "\"additionalDescription\": \"testDescription\"}";
const std::string TEST_VALUE_COMPLEXITYREG = "^(?=.*[a-zA-Z]).{1,9}$";
const int TEST_VALUE_VALIDITY_PERIOD = 2;
const std::string TEST_VALUE_ADDITIONAL_DESCRIPTION = "testDescription";
void PasswordPolicySerializerTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void PasswordPolicySerializerTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDeserializeEmpty
 * @tc.desc: Test PasswordSerializer::Deserialize when jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(PasswordPolicySerializerTest, TestDeserializeEmpty, TestSize.Level1)
{
    auto serializer = PasswordSerializer::GetInstance();
    std::string jsonString;
    PasswordPolicy policy;
    bool ret = serializer->Deserialize(jsonString, policy);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(policy.complexityReg.empty());
    ASSERT_TRUE(policy.validityPeriod == 0);
    ASSERT_TRUE(policy.additionalDescription.empty());
}

/**
 * @tc.name: TestDeserializeIllegal
 * @tc.desc: Test PasswordSerializer::Deserialize when jsonString is illegal
 * @tc.type: FUNC
 */
HWTEST_F(PasswordPolicySerializerTest, TestDeserializeIllegal, TestSize.Level1)
{
    auto serializer = PasswordSerializer::GetInstance();
    std::string jsonString = "{123";
    PasswordPolicy policy;
    bool ret = serializer->Deserialize(jsonString, policy);
    ASSERT_FALSE(ret);
    ASSERT_TRUE(policy.complexityReg.empty());
    ASSERT_TRUE(policy.validityPeriod == 0);
    ASSERT_TRUE(policy.additionalDescription.empty());
}

/**
 * @tc.name: TestDeserializeIllegal2
 * @tc.desc: Test PasswordSerializer::Deserialize when jsonString is illegal
 * @tc.type: FUNC
 */
HWTEST_F(PasswordPolicySerializerTest, TestDeserializeIllegal2, TestSize.Level1)
{
    auto serializer = PasswordSerializer::GetInstance();
    std::string jsonString = TEST_POLICY_DATA_ILEEGAL;
    PasswordPolicy policy;
    bool ret = serializer->Deserialize(jsonString, policy);
    ASSERT_FALSE(ret);
    ASSERT_TRUE(policy.complexityReg.empty());
    ASSERT_TRUE(policy.validityPeriod == 0);
    ASSERT_TRUE(policy.additionalDescription.empty());
}

/**
 * @tc.name: TestDeserializeSuc
 * @tc.desc: Test PasswordSerializer::Deserialize
 * @tc.type: FUNC
 */
HWTEST_F(PasswordPolicySerializerTest, TestDeserializeSuc, TestSize.Level1)
{
    auto serializer = PasswordSerializer::GetInstance();
    std::string jsonString = TEST_POLICY_DATA;
    PasswordPolicy policy;
    bool ret = serializer->Deserialize(jsonString, policy);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(policy.complexityReg == TEST_VALUE_COMPLEXITYREG);
    ASSERT_TRUE(policy.validityPeriod == TEST_VALUE_VALIDITY_PERIOD);
    ASSERT_TRUE(policy.additionalDescription == TEST_VALUE_ADDITIONAL_DESCRIPTION);
}

/**
 * @tc.name: TestSerializeSuc
 * @tc.desc: Test PasswordSerializer::Serialize
 * @tc.type: FUNC
 */
HWTEST_F(PasswordPolicySerializerTest, TestSerializeSuc, TestSize.Level1)
{
    auto serializer = PasswordSerializer::GetInstance();
    std::string jsonString;
    PasswordPolicy policy{TEST_VALUE_COMPLEXITYREG, TEST_VALUE_VALIDITY_PERIOD, TEST_VALUE_ADDITIONAL_DESCRIPTION};
    bool ret = serializer->Serialize(policy, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(jsonString.empty());
}

/**
 * @tc.name: TestGetPolicySuc
 * @tc.desc: Test PasswordSerializer::GetPolicy
 * @tc.type: FUNC
 */
HWTEST_F(PasswordPolicySerializerTest, TestGetPolicySuc, TestSize.Level1)
{
    auto serializer = PasswordSerializer::GetInstance();
    MessageParcel data;
    PasswordPolicy policy;
    data.WriteString(TEST_VALUE_COMPLEXITYREG);
    data.WriteInt64(TEST_VALUE_VALIDITY_PERIOD);
    data.WriteString(TEST_VALUE_ADDITIONAL_DESCRIPTION);
    bool ret = serializer->GetPolicy(data, policy);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(policy.complexityReg == TEST_VALUE_COMPLEXITYREG);
    ASSERT_TRUE(policy.validityPeriod == TEST_VALUE_VALIDITY_PERIOD);
    ASSERT_TRUE(policy.additionalDescription == TEST_VALUE_ADDITIONAL_DESCRIPTION);
}

/**
 * @tc.name: TestWritePolicySuc
 * @tc.desc: Test PasswordSerializer::WritePolicy
 * @tc.type: FUNC
 */
HWTEST_F(PasswordPolicySerializerTest, TestWritePolicySuc, TestSize.Level1)
{
    auto serializer = PasswordSerializer::GetInstance();
    MessageParcel reply;
    PasswordPolicy policy;
    bool ret = serializer->WritePolicy(reply, policy);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestMergePolicySuc
 * @tc.desc: Test PasswordSerializer::MergePolicy
 * @tc.type: FUNC
 */
HWTEST_F(PasswordPolicySerializerTest, TestMergePolicySuc, TestSize.Level1)
{
    auto serializer = PasswordSerializer::GetInstance();
    std::vector<PasswordPolicy> data;
    PasswordPolicy result;
    PasswordPolicy policy1{TEST_VALUE_COMPLEXITYREG, TEST_VALUE_VALIDITY_PERIOD, ""};
    PasswordPolicy policy2{"", 0, TEST_VALUE_ADDITIONAL_DESCRIPTION};
    data.push_back(policy1);
    data.push_back(policy2);
    serializer->MergePolicy(data, result);
    ASSERT_TRUE(result.complexityReg == TEST_VALUE_COMPLEXITYREG);
    ASSERT_TRUE(result.validityPeriod == TEST_VALUE_VALIDITY_PERIOD);
    ASSERT_TRUE(result.additionalDescription == TEST_VALUE_ADDITIONAL_DESCRIPTION);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
