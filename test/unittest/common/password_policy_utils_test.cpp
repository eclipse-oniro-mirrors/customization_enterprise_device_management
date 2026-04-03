/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License
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

#include "password_policy_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class PasswordPolicyUtilsTest : public testing::Test {
protected:
    void SetUp() override;
    void TearDown() override;
};

void PasswordPolicyUtilsTest::SetUp()
{
}

void PasswordPolicyUtilsTest::TearDown()
{
}

/**
 * @tc.name: TestUpdatePasswordPolicy
 * @tc.desc: Test UpdatePasswordPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordPolicyUtilsTest, TestUpdatePasswordPolicy, TestSize.Level1)
{
    PasswordPolicyUtils passwordPolicyUtils;
    PasswordPolicy policy;
    bool result = passwordPolicyUtils.GetPasswordPolicy(policy);
    EXPECT_TRUE(result);
    policy.complexityReg = "^(?=.*[a-zA-Z]).{1,9}$";
    policy.validityPeriod = 2;
    policy.additionalDescription = "testDescription";
    result = passwordPolicyUtils.UpdatePasswordPolicy(policy);
    EXPECT_TRUE(result);
    PasswordPolicy getPolicy;
    passwordPolicyUtils.GetPasswordPolicy(getPolicy);
    EXPECT_EQ(policy.complexityReg, getPolicy.complexityReg);
    EXPECT_EQ(policy.validityPeriod, getPolicy.validityPeriod);
    EXPECT_EQ(policy.additionalDescription, getPolicy.additionalDescription);
}

/**
 * @tc.name: TestUpdatePasswordPolicyWithNegativeValidityPeriod
 * @tc.desc: Test UpdatePasswordPolicy function with negative validityPeriod.
 * @tc.type: FUNC
 */
HWTEST_F(PasswordPolicyUtilsTest, TestUpdatePasswordPolicyWithNegativeValidityPeriod, TestSize.Level1)
{
    PasswordPolicyUtils passwordPolicyUtils;
    PasswordPolicy policy;
    policy.complexityReg = "";
    policy.validityPeriod = -1;
    policy.additionalDescription = "";
    bool result = passwordPolicyUtils.UpdatePasswordPolicy(policy);
    EXPECT_TRUE(result);
    PasswordPolicy getPolicy;
    passwordPolicyUtils.GetPasswordPolicy(getPolicy);
    EXPECT_TRUE(policy.complexityReg.empty());
    EXPECT_EQ(policy.validityPeriod, getPolicy.validityPeriod);
    EXPECT_TRUE(policy.additionalDescription.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS