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

#include "cJSON.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_POLICY_DATA = "{\"complexityReg\":\"^(?=.*[a-zA-Z]).{1,9}$\", \"validityPeriod\": 2,"
    "\"additionalDescription\": \"testDescription\"}";
const std::string TEST_VALUE_COMPLEXITYREG = "^(?=.*[a-zA-Z]).{1,9}$";
const int TEST_VALUE_VALIDITY_PERIOD = 2;
const std::string TEST_VALUE_ADDITIONAL_DESCRIPTION = "testDescription";
class PasswordSerializerTest : public testing::Test {};
/**
 * @tc.name: TestSerialize
 * @tc.desc: Test PasswordSerializer::Serialize func.
 * and policies is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordSerializerTest, TestSerialize, TestSize.Level1)
{
    PasswordPolicy policy;
    auto serializer = PasswordSerializer::GetInstance();
    std::string policyData = TEST_POLICY_DATA;
    ASSERT_TRUE(serializer->Deserialize(policyData, policy));
    ASSERT_TRUE(policy.additionalDescription == TEST_VALUE_ADDITIONAL_DESCRIPTION);
    ASSERT_TRUE(policy.validityPeriod == TEST_VALUE_VALIDITY_PERIOD);
    ASSERT_TRUE(policy.complexityReg == TEST_VALUE_COMPLEXITYREG);

    std::string result;
    ASSERT_TRUE(serializer->Serialize(policy, result));
    std::string jsonString = "";
    cJSON* root = cJSON_Parse(policyData.c_str());
    char* cJsonStr = cJSON_Print(root);
    if (cJsonStr != nullptr) {
        jsonString = std::string(cJsonStr);
        cJSON_free(cJsonStr);
    }
    cJSON_Delete(root);
    ASSERT_TRUE(jsonString == result);
}

/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test PasswordSerializer::WritePolicy func.
 * and policies is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordSerializerTest, TestWritePolicy, TestSize.Level1)
{
    MessageParcel reply;
    PasswordPolicy policy;
    auto serializer = PasswordSerializer::GetInstance();
    policy.additionalDescription = TEST_VALUE_ADDITIONAL_DESCRIPTION;
    policy.validityPeriod = TEST_VALUE_VALIDITY_PERIOD;
    policy.complexityReg = TEST_VALUE_COMPLEXITYREG;

    ASSERT_TRUE(serializer->WritePolicy(reply, policy));

    PasswordPolicy result;
    std::vector<PasswordPolicy> passwordPolicies{policy};

    ASSERT_TRUE(serializer->MergePolicy(passwordPolicies, result));

    ASSERT_TRUE(policy.additionalDescription == TEST_VALUE_ADDITIONAL_DESCRIPTION);
    ASSERT_TRUE(policy.validityPeriod == TEST_VALUE_VALIDITY_PERIOD);
    ASSERT_TRUE(policy.complexityReg == TEST_VALUE_COMPLEXITYREG);

    ASSERT_TRUE(serializer->GetPolicy(reply, result));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
