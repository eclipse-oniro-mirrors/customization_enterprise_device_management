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
#include <string>
#include "ipolicy_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_ADMIN_NAME = "com.edm.test.demo";
const std::string TEST_ADMIN_NAME1 = "com.edm.test.demo1";
const std::string TEST_STRING_POLICY_NAME = "testStringPolicy";
class IPolicyManagerTest : public testing::Test {};

/**
 * @tc.name: TestGetPolicy
 * @tc.desc: Test TestGetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(IPolicyManagerTest, TestGetPolicy, TestSize.Level1)
{
    ErrCode res;
    auto policyManager = IPolicyManager::GetInstance();
    std::string policyValue = "";
    res = policyManager->GetPolicy(TEST_ADMIN_NAME, TEST_STRING_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue.empty());
    res = policyManager->GetPolicy("", TEST_STRING_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue.empty());

    res = policyManager->GetPolicy(TEST_ADMIN_NAME1, TEST_STRING_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue.empty());
    res = policyManager->GetPolicy("", TEST_STRING_POLICY_NAME, policyValue);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(policyValue.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS