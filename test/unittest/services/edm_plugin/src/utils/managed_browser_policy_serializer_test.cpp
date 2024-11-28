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

#include "managed_browser_policy_serializer_test.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_POLICY_DATA = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"]}}";
const std::string TEST_BUNDLE_NAME = "test_bundle_name";
const std::string TEST_POLICY_NAME = "test_policy_name";
const std::string TEST_POLICY_VALUE = "\"test_policy_value\"";

void ManagedBrowserPolicySerializerTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ManagedBrowserPolicySerializerTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSerializeSuc
 * @tc.desc: Test ManagedBrowserPolicySerializer::Serialize success
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeSuc, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    dataObj[TEST_BUNDLE_NAME].version = 1;
    dataObj[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string policyData;
    bool ret = serializer->Serialize(dataObj, policyData);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(policyData.empty());
}

/**
 * @tc.name: TestDeserializeEmpty
 * @tc.desc: Test ManagedBrowserPolicySerializer::Deserialize when policy is empty
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeEmpty, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::string emptyPolicy;
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    bool ret = serializer->Deserialize(emptyPolicy, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(dataObj.empty());
}

/**
 * @tc.name: TestDeserializeSuc
 * @tc.desc: Test ManagedBrowserPolicySerializer::Deserialize success
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeSuc, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    bool ret = serializer->Deserialize(TEST_POLICY_DATA, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(dataObj[TEST_BUNDLE_NAME].version == 1);
    ASSERT_TRUE(dataObj[TEST_BUNDLE_NAME].policyNames.size() == 1);
}

/**
 * @tc.name: TestDeserializeFail
 * @tc.desc: Test ManagedBrowserPolicySerializer::Deserialize failed
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeFail, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    const std::string policy = "invalid";
    bool ret = serializer->Deserialize(policy, dataObj);
    ASSERT_FALSE(ret);
    ASSERT_TRUE(dataObj.empty());
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS