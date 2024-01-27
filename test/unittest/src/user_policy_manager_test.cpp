/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <string>
#include <vector>
#include "array_string_serializer.h"
#include "user_policy_manager.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_ADMIN_NAME = "com.edm.test.demo";
const std::string TEST_ADMIN_NAME1 = "com.edm.test.demo1";
const std::string TEST_BOOL_POLICY_NAME = "testBoolPolicy";
const std::string TEST_STRING_POLICY_NAME = "testStringPolicy";
const std::string TEST_ADMIN_POLICY_VALUE = "adminPolicy";
const std::string TEST_MERAGE_POLICY_VALUE = "mergedValue";
const std::string TEST_MERAGE_POLICY_VALUE_ONE = "mergedValue1";
constexpr int HUGE_POLICY_SIZE = 65537;
constexpr int32_t DEFAULT_USER_ID = 100;

class UserPolicyManagerTest : public testing::Test {
public:
    void SetUp() override
    {
        if (!userPolicyMgr_) {
            userPolicyMgr_ = std::make_shared<UserPolicyManager>(DEFAULT_USER_ID);
        }
        userPolicyMgr_->Init();
    }

    void TearDown() override
    {
        userPolicyMgr_ = nullptr;
    }

    std::shared_ptr<UserPolicyManager> userPolicyMgr_;
};

/**
 * @tc.name: TestSetPolicy
 * @tc.desc: Test UserPolicyManager SetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(UserPolicyManagerTest, TestSetPolicy, TestSize.Level1)
{
    ErrCode res;
    std::string adminPolicy;
    std::string mergedPolicy;
    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, "false", "true");
    ASSERT_TRUE(res == ERR_OK);

    std::string policyValue;
    res = userPolicyMgr_->GetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "false");
    res = userPolicyMgr_->GetPolicy("", TEST_BOOL_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "true");

    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME1, TEST_BOOL_POLICY_NAME, "true", "true");
    ASSERT_TRUE(res == ERR_OK);
    res = userPolicyMgr_->GetPolicy(TEST_ADMIN_NAME1, TEST_BOOL_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "true");
    res = userPolicyMgr_->GetPolicy("", TEST_BOOL_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "true");

    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME1, TEST_BOOL_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestGetPolicy
 * @tc.desc: Test UserPolicyManager GetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(UserPolicyManagerTest, TestGetPolicy, TestSize.Level1)
{
    ErrCode res;
    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_STRING_POLICY_NAME, TEST_ADMIN_POLICY_VALUE,
        TEST_MERAGE_POLICY_VALUE);
    ASSERT_TRUE(res == ERR_OK);

    std::string policyValue;
    res = userPolicyMgr_->GetPolicy(TEST_ADMIN_NAME, TEST_STRING_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == TEST_ADMIN_POLICY_VALUE);
    res = userPolicyMgr_->GetPolicy("", TEST_STRING_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == TEST_MERAGE_POLICY_VALUE);

    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME1, TEST_STRING_POLICY_NAME, "", TEST_MERAGE_POLICY_VALUE_ONE);
    ASSERT_TRUE(res == ERR_OK);

    policyValue = "";
    res = userPolicyMgr_->GetPolicy(TEST_ADMIN_NAME1, TEST_STRING_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_EDM_POLICY_NOT_FIND);
    ASSERT_TRUE(policyValue.empty());
    res = userPolicyMgr_->GetPolicy("", TEST_STRING_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == TEST_MERAGE_POLICY_VALUE_ONE);

    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_STRING_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME1, TEST_STRING_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: GetAllPolicyByAdmin
 * @tc.desc: Test PolicyManager GetAllPolicyByAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(UserPolicyManagerTest, TestGetAdminAllPolicy, TestSize.Level1)
{
    ErrCode res;
    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_STRING_POLICY_NAME, TEST_ADMIN_POLICY_VALUE,
        TEST_MERAGE_POLICY_VALUE);
    ASSERT_TRUE(res == ERR_OK);
    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, "true", "true");
    ASSERT_TRUE(res == ERR_OK);

    std::unordered_map<std::string, std::string> allPolicyValue;
    res = userPolicyMgr_->GetAllPolicyByAdmin(TEST_ADMIN_NAME, allPolicyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(allPolicyValue.size() == 2);
    auto stringEntry = allPolicyValue.find(TEST_STRING_POLICY_NAME);
    ASSERT_TRUE(stringEntry != allPolicyValue.end() && stringEntry->second == TEST_ADMIN_POLICY_VALUE);
    auto boolEntry = allPolicyValue.find(TEST_BOOL_POLICY_NAME);
    ASSERT_TRUE(boolEntry != allPolicyValue.end() && boolEntry->second == "true");

    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestGetAdminByPolicyName
 * @tc.desc: Test UserPolicyManager GetAdminByPolicyName func.
 * @tc.type: FUNC
 */
HWTEST_F(UserPolicyManagerTest, TestGetAdminByPolicyName, TestSize.Level1)
{
    ErrCode res;
    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, "false", "true");
    ASSERT_TRUE(res == ERR_OK);
    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME1, TEST_BOOL_POLICY_NAME, "true", "true");
    ASSERT_TRUE(res == ERR_OK);

    std::unordered_map<std::string, std::string> adminPolicyValue;
    res = userPolicyMgr_->GetAdminByPolicyName(TEST_BOOL_POLICY_NAME, adminPolicyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(adminPolicyValue.size() == 2);
    auto adminEntry = adminPolicyValue.find(TEST_ADMIN_NAME);
    ASSERT_TRUE(adminEntry != adminPolicyValue.end() && adminEntry->second == "false");
    auto adminEntry1 = adminPolicyValue.find(TEST_ADMIN_NAME1);
    ASSERT_TRUE(adminEntry1 != adminPolicyValue.end() && adminEntry1->second == "true");

    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME1, TEST_BOOL_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestSetPolicyHuge
 * @tc.desc: Test UserPolicyManager SetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(UserPolicyManagerTest, TestSetPolicyHuge, TestSize.Level1)
{
    std::vector<std::string> hugeArrayPolicy;
    for (int i = 0; i < HUGE_POLICY_SIZE; ++i) {
        std::string s1 = "hugeArrayPolicyValue:" + std::to_string(i);
        hugeArrayPolicy.emplace_back(s1);
    }
    ErrCode res;
    std::string policyValue;
    ASSERT_TRUE(ArrayStringSerializer::GetInstance()->Serialize(hugeArrayPolicy, policyValue));
    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_STRING_POLICY_NAME, policyValue, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME1, TEST_STRING_POLICY_NAME, policyValue, policyValue);
    ASSERT_TRUE(res == ERR_OK);

    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_STRING_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
    res = userPolicyMgr_->SetPolicy(TEST_ADMIN_NAME1, TEST_STRING_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
