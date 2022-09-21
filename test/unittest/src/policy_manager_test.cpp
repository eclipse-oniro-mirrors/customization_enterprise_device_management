/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "cmd_utils.h"
#include "policy_manager.h"
#include "array_string_serializer.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_ADMIN_NAME = "com.edm.test.demo";
const std::string TEST_ADMIN_NAME1 = "com.edm.test.demo1";
const std::string TEST_BOOL_POLICY_NAME = "testBoolPolicy";
const std::string TEST_STRING_POLICY_NAME = "testStringPolicy";
constexpr int HUGE_POLICY_SIZE = 65537;
const std::string TEAR_DOWN_CMD = "rm /data/service/el1/public/edm/device_policies.json";

class PolicyManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        PolicyManager::GetInstance()->Init();
    }

protected:
    void TearDown() override
    {
        PolicyManager::GetInstance()->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME, "", "");
        PolicyManager::GetInstance()->SetPolicy(TEST_ADMIN_NAME1, TEST_BOOL_POLICY_NAME, "", "");

        PolicyManager::GetInstance()->SetPolicy(TEST_ADMIN_NAME, TEST_STRING_POLICY_NAME, "", "");
        PolicyManager::GetInstance()->SetPolicy(TEST_ADMIN_NAME1, TEST_STRING_POLICY_NAME, "", "");

        CmdUtils::ExecCmdSync(TEAR_DOWN_CMD);
    }
};

/**
 * @tc.name: TestSetPolicy
 * @tc.desc: Test PolicyManager SetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(PolicyManagerTest, TestSetPolicy, TestSize.Level1)
{
    ErrCode res;
    std::string adminName = TEST_ADMIN_NAME;
    std::string policyName = TEST_BOOL_POLICY_NAME;
    std::string adminName1 = TEST_ADMIN_NAME1;
    std::string adminPolicy;
    std::string mergedPolicy;
    res = PolicyManager::GetInstance()->SetPolicy(adminName, policyName, "false", "true");
    ASSERT_TRUE(res == ERR_OK);

    std::string policyValue;
    res = PolicyManager::GetInstance()->GetPolicy(adminName, policyName, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "false");
    res = PolicyManager::GetInstance()->GetPolicy("", policyName, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "true");

    res = PolicyManager::GetInstance()->SetPolicy(adminName1, policyName, "true", "true");
    ASSERT_TRUE(res == ERR_OK);
    res = PolicyManager::GetInstance()->GetPolicy(adminName, policyName, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "false");
    res = PolicyManager::GetInstance()->GetPolicy("", policyName, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "true");
}

/**
 * @tc.name: TestGetPolicy
 * @tc.desc: Test PolicyManager GetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(PolicyManagerTest, TestGetPolicy, TestSize.Level1)
{
    ErrCode res;
    std::string adminName = TEST_ADMIN_NAME;
    std::string policyName = TEST_STRING_POLICY_NAME;
    std::string adminPolicy = "adminPolicy";
    std::string mergedPolicy = "mergedValue";
    res = PolicyManager::GetInstance()->SetPolicy(adminName, policyName, adminPolicy, mergedPolicy);
    ASSERT_TRUE(res == ERR_OK);

    std::string policyValue;
    res = PolicyManager::GetInstance()->GetPolicy(adminName, policyName, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "adminPolicy");
    res = PolicyManager::GetInstance()->GetPolicy("", policyName, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "mergedValue");

    res = PolicyManager::GetInstance()->SetPolicy(TEST_ADMIN_NAME1, policyName, "", "mergedValue1");
    ASSERT_TRUE(res == ERR_OK);

    res = PolicyManager::GetInstance()->GetPolicy(adminName, policyName, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "adminPolicy");
    res = PolicyManager::GetInstance()->GetPolicy("", policyName, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue == "mergedValue1");
}

/**
 * @tc.name: GetAllPolicyByAdmin
 * @tc.desc: Test PolicyManager GetAllPolicyByAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(PolicyManagerTest, TestGetAdminAllPolicy, TestSize.Level1)
{
    ErrCode res;
    res = PolicyManager::GetInstance()->SetPolicy(TEST_ADMIN_NAME, TEST_STRING_POLICY_NAME,
        "adminPolicy", "mergedValue");
    ASSERT_TRUE(res == ERR_OK);
    res = PolicyManager::GetInstance()->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME,
        "true", "true");
    ASSERT_TRUE(res == ERR_OK);

    std::unordered_map<std::string, std::string> allPolicyValue;
    res = PolicyManager::GetInstance()->GetAllPolicyByAdmin(TEST_ADMIN_NAME, allPolicyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(allPolicyValue.size() == 2);
    auto stringEntry = allPolicyValue.find(TEST_STRING_POLICY_NAME);
    ASSERT_TRUE(stringEntry != allPolicyValue.end() && stringEntry->second == "adminPolicy");
    auto boolEntry = allPolicyValue.find(TEST_BOOL_POLICY_NAME);
    ASSERT_TRUE(boolEntry != allPolicyValue.end() && boolEntry->second == "true");
}

/**
 * @tc.name: TestGetAdminByPolicyName
 * @tc.desc: Test PolicyManager GetAdminByPolicyName func.
 * @tc.type: FUNC
 */
HWTEST_F(PolicyManagerTest, TestGetAdminByPolicyName, TestSize.Level1)
{
    ErrCode res;
    res = PolicyManager::GetInstance()->SetPolicy(TEST_ADMIN_NAME, TEST_BOOL_POLICY_NAME,
        "false", "true");
    ASSERT_TRUE(res == ERR_OK);
    res = PolicyManager::GetInstance()->SetPolicy(TEST_ADMIN_NAME1, TEST_BOOL_POLICY_NAME,
        "true", "true");
    ASSERT_TRUE(res == ERR_OK);

    std::unordered_map<std::string, std::string> adminPolicyValue;
    res = PolicyManager::GetInstance()->GetAdminByPolicyName(TEST_BOOL_POLICY_NAME, adminPolicyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(adminPolicyValue.size() == 2);
    auto adminEntry = adminPolicyValue.find(TEST_ADMIN_NAME);
    ASSERT_TRUE(adminEntry != adminPolicyValue.end() && adminEntry->second == "false");
    auto adminEntry1 = adminPolicyValue.find(TEST_ADMIN_NAME1);
    ASSERT_TRUE(adminEntry1 != adminPolicyValue.end() && adminEntry1->second == "true");
}

/**
 * @tc.name: TestSetPolicyHuge
 * @tc.desc: Test PolicyManager SetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(PolicyManagerTest, TestSetPolicyHuge, TestSize.Level1)
{
    std::vector<std::string> hugeArrayPolicy;
    for (int i = 0; i < HUGE_POLICY_SIZE; ++i) {
        std::string s1 = "hugeArrayPolicyValue:" + std::to_string(i);
        hugeArrayPolicy.emplace_back(s1);
    }
    ErrCode res;
    std::string policyValue;
    ASSERT_TRUE(ArrayStringSerializer::GetInstance()->Serialize(hugeArrayPolicy, policyValue));
    res = PolicyManager::GetInstance()->SetPolicy(TEST_ADMIN_NAME, TEST_STRING_POLICY_NAME,
        policyValue, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    res = PolicyManager::GetInstance()->SetPolicy(TEST_ADMIN_NAME1, TEST_STRING_POLICY_NAME,
        policyValue, policyValue);
    ASSERT_TRUE(res == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
