/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#define private public
#include "policy_manager.h"
#undef private
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
constexpr int32_t TEST_USER_ID = 101;
constexpr int32_t DEFAULT_USERID = 100;

class PolicyManagerTest : public testing::Test {
public:
    void SetUp() override
    {
        if (!policyMgr_) {
            policyMgr_ = std::make_shared<PolicyManager>();
        }
        std::vector<int32_t> userIds {TEST_USER_ID};
        policyMgr_->Init(userIds);
    }

    void TearDown() override
    {
        policyMgr_ = nullptr;
    }

    std::shared_ptr<PolicyManager> policyMgr_;
};

/**
 * @tc.name: TestGetAdminByPolicyName
 * @tc.desc: Test PolicyManager GetAdminByPolicyName func.
 * @tc.type: FUNC
 */
HWTEST_F(PolicyManagerTest, TestGetAdminByPolicyName, TestSize.Level1)
{
    ErrCode res;
    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, "false", "true");
    ASSERT_TRUE(res == ERR_OK);
    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME1, TEST_BOOL_POLICY_NAME, "true", "true");
    ASSERT_TRUE(res == ERR_OK);

    std::unordered_map<std::string, std::string> adminPolicyValue;
    res = policyMgr_->GetAdminByPolicyName(TEST_BOOL_POLICY_NAME, adminPolicyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(adminPolicyValue.size() == 2);
    auto adminEntry = adminPolicyValue.find(TEST_ADMIN_NAME);
    ASSERT_TRUE(adminEntry != adminPolicyValue.end() && adminEntry->second == "false");
    auto adminEntry1 = adminPolicyValue.find(TEST_ADMIN_NAME1);
    ASSERT_TRUE(adminEntry1 != adminPolicyValue.end() && adminEntry1->second == "true");

    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME1, TEST_BOOL_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestGetPolicy
 * @tc.desc: Test PolicyManager GetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(PolicyManagerTest, TestGetPolicy, TestSize.Level1)
{
    ErrCode res;
    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_STRING_POLICY_NAME, TEST_ADMIN_POLICY_VALUE,
        TEST_MERAGE_POLICY_VALUE);
    ASSERT_TRUE(res == ERR_OK);

    std::string policyValue;
    res = policyMgr_->GetPolicy(TEST_ADMIN_NAME, TEST_STRING_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == TEST_ADMIN_POLICY_VALUE);
    res = policyMgr_->GetPolicy("", TEST_STRING_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == TEST_MERAGE_POLICY_VALUE);

    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME1, TEST_STRING_POLICY_NAME, "", TEST_MERAGE_POLICY_VALUE_ONE);
    ASSERT_TRUE(res == ERR_OK);

    policyValue = "";
    res = policyMgr_->GetPolicy(TEST_ADMIN_NAME1, TEST_STRING_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_EDM_POLICY_NOT_FIND);
    ASSERT_TRUE(policyValue.empty());
    res = policyMgr_->GetPolicy("", TEST_STRING_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == TEST_MERAGE_POLICY_VALUE_ONE);

    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_STRING_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME1, TEST_STRING_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestSetPolicy
 * @tc.desc: Test PolicyManager SetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(PolicyManagerTest, TestSetPolicy, TestSize.Level1)
{
    ErrCode res;
    std::string adminPolicy;
    std::string mergedPolicy;
    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, "false", "true");
    ASSERT_TRUE(res == ERR_OK);

    std::string policyValue;
    res = policyMgr_->GetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "false");
    res = policyMgr_->GetPolicy("", TEST_BOOL_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "true");

    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME1, TEST_BOOL_POLICY_NAME, "true", "true");
    ASSERT_TRUE(res == ERR_OK);
    res = policyMgr_->GetPolicy(TEST_ADMIN_NAME1, TEST_BOOL_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "true");
    res = policyMgr_->GetPolicy("", TEST_BOOL_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "true");

    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME1, TEST_BOOL_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestGetAllPolicyByAdmin
 * @tc.desc: Test PolicyManager GetAllPolicyByAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(PolicyManagerTest, TestGetAllPolicyByAdmin, TestSize.Level1)
{
    ErrCode res;
    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_STRING_POLICY_NAME, TEST_ADMIN_POLICY_VALUE,
        TEST_MERAGE_POLICY_VALUE);
    ASSERT_TRUE(res == ERR_OK);
    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, "true", "true");
    ASSERT_TRUE(res == ERR_OK);

    std::unordered_map<std::string, std::string> allPolicyValue;
    res = policyMgr_->GetAllPolicyByAdmin(TEST_ADMIN_NAME, allPolicyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(allPolicyValue.size() == 2);
    auto stringEntry = allPolicyValue.find(TEST_STRING_POLICY_NAME);
    ASSERT_TRUE(stringEntry != allPolicyValue.end() && stringEntry->second == TEST_ADMIN_POLICY_VALUE);
    auto boolEntry = allPolicyValue.find(TEST_BOOL_POLICY_NAME);
    ASSERT_TRUE(boolEntry != allPolicyValue.end() && boolEntry->second == "true");

    res = policyMgr_->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, "", "");
    ASSERT_TRUE(res == ERR_OK);
}

/**
 * @tc.name: TestGetPolicyUserIds
 * @tc.desc: Test PolicyManager GetPolicyUserIds func.
 * @tc.type: FUNC
 */
HWTEST_F(PolicyManagerTest, TestGetPolicyUserIds, TestSize.Level1)
{
    std::vector<int32_t> userIds;
    policyMgr_->GetPolicyUserIds(userIds);
    ASSERT_TRUE(userIds.size() == 1);
    ASSERT_TRUE(userIds[0] == TEST_USER_ID);

    ASSERT_TRUE(policyMgr_->GetUserPolicyMgr(102) != nullptr);

    userIds = {};
    policyMgr_->GetPolicyUserIds(userIds);
    ASSERT_TRUE(userIds.size() == 2);
}

/**
 * @tc.name: TestGetUserPolicyMgr
 * @tc.desc: Test PolicyManager GetUserPolicyMgr func.
 * @tc.type: FUNC
 */
HWTEST_F(PolicyManagerTest, TestGetUserPolicyMgr, TestSize.Level1)
{
    ASSERT_TRUE(policyMgr_->GetUserPolicyMgr(DEFAULT_USERID) != nullptr);
    ASSERT_TRUE(policyMgr_->GetUserPolicyMgr(TEST_USER_ID) != nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
