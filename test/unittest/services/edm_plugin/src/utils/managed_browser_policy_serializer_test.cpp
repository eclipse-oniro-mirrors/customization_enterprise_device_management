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
const std::string TEST_OTHER_BUNDLE_NAME = "other_bundle_name";
const std::string TEST_OTHER_POLICY_NAME = "other_policy_name";

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

/**
 * @tc.name: TestSerializeWritesOnlyVersionAndPolicyNames
 * @tc.desc: The serialized blob carries the version and the policy names only, so the policy
 *           ownership is not duplicated inside the stored data.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeWritesOnlyVersionAndPolicyNames, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    dataObj[TEST_BUNDLE_NAME].version = 3;
    dataObj[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string policyData;
    ASSERT_TRUE(serializer->Serialize(dataObj, policyData));
    EXPECT_NE(policyData.find("\"version\""), std::string::npos);
    EXPECT_NE(policyData.find("\"policyNames\""), std::string::npos);
    EXPECT_EQ(policyData.find("ownership"), std::string::npos);
    EXPECT_EQ(policyData.find("adminBundleName"), std::string::npos);
    EXPECT_EQ(policyData.find("isForceOverride"), std::string::npos);
}

/**
 * @tc.name: TestDeserializeLegacyDataWithOwnershipField
 * @tc.desc: Data persisted while the ownership records existed is still readable, the ownership
 *           field is ignored and the policy names are kept unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeLegacyDataWithOwnershipField, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":{\"test_policy_name\":{\"adminBundleName\":\"com.admin.a\",\"isForceOverride\":true}}}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    ASSERT_EQ(dataObj[TEST_BUNDLE_NAME].version, 1);
    ASSERT_EQ(dataObj[TEST_BUNDLE_NAME].policyNames.size(), 1);
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].policyNames[0], TEST_POLICY_NAME);
}

/**
 * @tc.name: TestDeserializeLegacyDataWithoutOwnershipField
 * @tc.desc: Data persisted before the force override feature has no ownership field and loads
 *           with the plain policy names.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeLegacyDataWithoutOwnershipField, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(TEST_POLICY_DATA, dataObj));
    ASSERT_TRUE(dataObj[TEST_BUNDLE_NAME].version == 1);
    ASSERT_TRUE(dataObj[TEST_BUNDLE_NAME].policyNames.size() == 1);
}

/**
 * @tc.name: TestDeserializeToleratesNonObjectOwnershipField
 * @tc.desc: An ownership field that is not an object does not break the deserialization, so a
 *           blob written by an older version stays usable.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeToleratesNonObjectOwnershipField, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":\"com.admin.a\"}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    ASSERT_EQ(dataObj[TEST_BUNDLE_NAME].policyNames.size(), 1);
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].policyNames[0], TEST_POLICY_NAME);
}

/**
 * @tc.name: TestDeserializeToleratesNullOwnershipField
 * @tc.desc: A null ownership field does not break the deserialization of the policy names.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeToleratesNullOwnershipField, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":null}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    ASSERT_EQ(dataObj[TEST_BUNDLE_NAME].policyNames.size(), 1);
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].policyNames[0], TEST_POLICY_NAME);
}

/**
 * @tc.name: TestDeserializeOwnershipOfEmptyObject
 * @tc.desc: An empty ownership object does not change the policy names of the bundle.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeOwnershipOfEmptyObject, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":{}}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    ASSERT_EQ(dataObj[TEST_BUNDLE_NAME].policyNames.size(), 1);
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].policyNames[0], TEST_POLICY_NAME);
}

/**
 * @tc.name: TestSerializeDeserializeRoundTrip
 * @tc.desc: The version and the policy names survive a serialize and deserialize round trip.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeDeserializeRoundTrip, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    dataObj[TEST_BUNDLE_NAME].version = 2;
    dataObj[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string policyData;
    ASSERT_TRUE(serializer->Serialize(dataObj, policyData));
    std::map<std::string, ManagedBrowserPolicyType> result;
    ASSERT_TRUE(serializer->Deserialize(policyData, result));
    ASSERT_EQ(result[TEST_BUNDLE_NAME].version, 2);
    ASSERT_EQ(result[TEST_BUNDLE_NAME].policyNames.size(), 1);
    EXPECT_EQ(result[TEST_BUNDLE_NAME].policyNames[0], TEST_POLICY_NAME);
}

/**
 * @tc.name: TestSerializeDeserializeSeveralPoliciesOfOneBundle
 * @tc.desc: Several policy names of the same bundle are all kept by the round trip.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeDeserializeSeveralPoliciesOfOneBundle, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    dataObj[TEST_BUNDLE_NAME].version = 4;
    dataObj[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    dataObj[TEST_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    std::string policyData;
    ASSERT_TRUE(serializer->Serialize(dataObj, policyData));
    std::map<std::string, ManagedBrowserPolicyType> result;
    ASSERT_TRUE(serializer->Deserialize(policyData, result));
    ASSERT_EQ(result[TEST_BUNDLE_NAME].policyNames.size(), 2);
    EXPECT_EQ(result[TEST_BUNDLE_NAME].policyNames[0], TEST_POLICY_NAME);
    EXPECT_EQ(result[TEST_BUNDLE_NAME].policyNames[1], TEST_OTHER_POLICY_NAME);
}

/**
 * @tc.name: TestSerializeDeserializeOwnershipAcrossBundles
 * @tc.desc: Every bundle of the blob keeps its own policy names, the ownership records of the
 *           older format do not mix the bundles up.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeDeserializeOwnershipAcrossBundles, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":{\"test_policy_name\":{\"adminBundleName\":\"com.admin.a\",\"isForceOverride\":false}}},"
        "\"other_bundle_name\":{\"version\":2,\"policyNames\":[\"other_policy_name\"],"
        "\"ownership\":{\"other_policy_name\":{\"adminBundleName\":\"com.admin.b\",\"isForceOverride\":false}}}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    ASSERT_EQ(dataObj[TEST_BUNDLE_NAME].policyNames.size(), 1);
    ASSERT_EQ(dataObj[TEST_OTHER_BUNDLE_NAME].policyNames.size(), 1);
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].policyNames[0], TEST_POLICY_NAME);
    EXPECT_EQ(dataObj[TEST_OTHER_BUNDLE_NAME].policyNames[0], TEST_OTHER_POLICY_NAME);
}

/**
 * @tc.name: TestSerializeDeserializeSeveralBundles
 * @tc.desc: Several bundles are serialized and deserialized independently of each other.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeDeserializeSeveralBundles, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    dataObj[TEST_BUNDLE_NAME].version = 1;
    dataObj[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    dataObj[TEST_OTHER_BUNDLE_NAME].version = 5;
    dataObj[TEST_OTHER_BUNDLE_NAME].policyNames.push_back(TEST_OTHER_POLICY_NAME);
    std::string policyData;
    ASSERT_TRUE(serializer->Serialize(dataObj, policyData));
    std::map<std::string, ManagedBrowserPolicyType> result;
    ASSERT_TRUE(serializer->Deserialize(policyData, result));
    ASSERT_EQ(result.size(), 2);
    ASSERT_EQ(result[TEST_BUNDLE_NAME].version, 1);
    ASSERT_EQ(result[TEST_OTHER_BUNDLE_NAME].version, 5);
    EXPECT_EQ(result[TEST_OTHER_BUNDLE_NAME].policyNames[0], TEST_OTHER_POLICY_NAME);
}

/**
 * @tc.name: TestSerializeEmptyMap
 * @tc.desc: An empty map is serialized into an empty object and read back as an empty map.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeEmptyMap, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    std::string policyData;
    ASSERT_TRUE(serializer->Serialize(dataObj, policyData));
    std::map<std::string, ManagedBrowserPolicyType> result;
    ASSERT_TRUE(serializer->Deserialize(policyData, result));
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: TestDeserializeFailWithMalformedPolicyNames
 * @tc.desc: A policy list that is not an array makes the deserialization fail.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeFailWithMalformedPolicyNames, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":\"test_policy_name\"}}";
    EXPECT_FALSE(serializer->Deserialize(policy, dataObj));
}

/**
 * @tc.name: TestDeserializeFailWithNonStringPolicyNameEntry
 * @tc.desc: A policy name that is not a string makes the deserialization fail.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeFailWithNonStringPolicyNameEntry, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[123]}}";
    EXPECT_FALSE(serializer->Deserialize(policy, dataObj));
}

/**
 * @tc.name: TestDeserializeFailWithMissingVersion
 * @tc.desc: A blob without the version makes the deserialization fail.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeFailWithMissingVersion, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    const std::string policy = "{\"test_bundle_name\":{\"policyNames\":[\"test_policy_name\"]}}";
    EXPECT_FALSE(serializer->Deserialize(policy, dataObj));
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
