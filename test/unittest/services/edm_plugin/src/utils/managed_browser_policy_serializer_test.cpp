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

/**
 * @tc.name: TestDeserializeLegacyDataWithoutOwnership
 * @tc.desc: Data persisted before force override has no ownership field and must load with no owner.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeLegacyDataWithoutOwnership, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(TEST_POLICY_DATA, dataObj));
    ASSERT_TRUE(dataObj[TEST_BUNDLE_NAME].version == 1);
    ASSERT_TRUE(dataObj[TEST_BUNDLE_NAME].policyNames.size() == 1);
    ASSERT_TRUE(dataObj[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestSerializeAndDeserializeWithOwnership
 * @tc.desc: Ownership records survive a serialize and deserialize round trip.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeAndDeserializeWithOwnership, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    dataObj[TEST_BUNDLE_NAME].version = 2;
    dataObj[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = "com.admin.b";
    owner.isForceOverride = true;
    dataObj[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;

    std::string policyData;
    ASSERT_TRUE(serializer->Serialize(dataObj, policyData));
    ASSERT_TRUE(policyData.find("ownership") != std::string::npos);

    std::map<std::string, ManagedBrowserPolicyType> result;
    ASSERT_TRUE(serializer->Deserialize(policyData, result));
    ASSERT_TRUE(result[TEST_BUNDLE_NAME].ownership.size() == 1);
    ASSERT_TRUE(result[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName == "com.admin.b");
    ASSERT_TRUE(result[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestSerializeOmitsEmptyOwnership
 * @tc.desc: An empty ownership map keeps the legacy serialized shape unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeOmitsEmptyOwnership, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    dataObj[TEST_BUNDLE_NAME].version = 1;
    dataObj[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    std::string policyData;
    ASSERT_TRUE(serializer->Serialize(dataObj, policyData));
    ASSERT_TRUE(policyData.find("ownership") == std::string::npos);
}

/**
 * @tc.name: TestDeserializeToleratesMalformedOwnershipEntry
 * @tc.desc: A malformed ownership entry is skipped instead of failing the whole blob.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeToleratesMalformedOwnershipEntry, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":{\"test_policy_name\":{\"adminBundleName\":123}}}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    ASSERT_TRUE(dataObj[TEST_BUNDLE_NAME].version == 1);
    ASSERT_TRUE(dataObj[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestDeserializeKeepsValidOwnershipAndSkipsInvalidSibling
 * @tc.desc: A valid ownership entry is kept while its malformed sibling is dropped, so one
 *           bad record does not discard the ownership of the other policies.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeKeepsValidOwnershipAndSkipsInvalidSibling,
    TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":{\"good_policy\":{\"adminBundleName\":\"com.admin.a\",\"isForceOverride\":true},"
        "\"bad_policy\":{\"adminBundleName\":123,\"isForceOverride\":true}}}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    ASSERT_EQ(dataObj[TEST_BUNDLE_NAME].ownership.size(), 1);
    ASSERT_EQ(dataObj[TEST_BUNDLE_NAME].ownership.count("good_policy"), 1);
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].ownership["good_policy"].adminBundleName, "com.admin.a");
    EXPECT_TRUE(dataObj[TEST_BUNDLE_NAME].ownership["good_policy"].isForceOverride);
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].ownership.count("bad_policy"), 0);
}

/**
 * @tc.name: TestDeserializeSkipsOwnershipWithMissingForceFlag
 * @tc.desc: An ownership entry without the isForceOverride field is skipped, so a truncated
 *           record cannot mark a policy as owned by an unknown admin.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeSkipsOwnershipWithMissingForceFlag, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":{\"test_policy_name\":{\"adminBundleName\":\"com.admin.a\"}}}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    EXPECT_TRUE(dataObj[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestDeserializeSkipsOwnershipWithNonBoolForceFlag
 * @tc.desc: A numeric isForceOverride value is skipped because the field must be a bool, so
 *           a numeric 1 cannot be read back as a force override write.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeSkipsOwnershipWithNonBoolForceFlag, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":{\"test_policy_name\":{\"adminBundleName\":\"com.admin.a\",\"isForceOverride\":1}}}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    EXPECT_TRUE(dataObj[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestDeserializeSkipsOwnershipWithMissingAdminName
 * @tc.desc: An ownership entry without an admin name is skipped, so an empty owner never
 *           blocks a plain set from another admin.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeSkipsOwnershipWithMissingAdminName, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":{\"test_policy_name\":{\"isForceOverride\":true}}}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    EXPECT_TRUE(dataObj[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestDeserializeToleratesNonObjectOwnershipField
 * @tc.desc: An ownership field that is not an object is ignored and the policy itself still
 *           deserializes, so a corrupted field type does not lose the policy list.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeToleratesNonObjectOwnershipField, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":[\"com.admin.a\"]}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].policyNames.size(), 1);
    EXPECT_TRUE(dataObj[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestDeserializeToleratesNullOwnershipField
 * @tc.desc: A null ownership field is treated as no recorded owner.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeToleratesNullOwnershipField, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":null}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].policyNames.size(), 1);
    EXPECT_TRUE(dataObj[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestDeserializeOwnershipOfEmptyObject
 * @tc.desc: An empty ownership object deserializes successfully and leaves the map empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeOwnershipOfEmptyObject, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":{}}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].policyNames.size(), 1);
    EXPECT_TRUE(dataObj[TEST_BUNDLE_NAME].ownership.empty());
}

/**
 * @tc.name: TestSerializeDeserializeForceOverrideFalseRoundTrip
 * @tc.desc: A non force override write keeps isForceOverride false across a round trip, so a
 *           plain set is not mistaken for a takeover after the service restarts.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeDeserializeForceOverrideFalseRoundTrip, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    dataObj[TEST_BUNDLE_NAME].version = 1;
    dataObj[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = "com.admin.a";
    owner.isForceOverride = false;
    dataObj[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;

    std::string policyData;
    ASSERT_TRUE(serializer->Serialize(dataObj, policyData));
    EXPECT_NE(policyData.find("\"isForceOverride\":false"), std::string::npos);

    std::map<std::string, ManagedBrowserPolicyType> result;
    ASSERT_TRUE(serializer->Deserialize(policyData, result));
    ASSERT_EQ(result[TEST_BUNDLE_NAME].ownership.count(TEST_POLICY_NAME), 1);
    EXPECT_EQ(result[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, "com.admin.a");
    EXPECT_FALSE(result[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestSerializeDeserializeMultipleOwnershipPerBundle
 * @tc.desc: Every ownership record of a bundle is persisted, so a bundle with several owned
 *           policies keeps each of its owners distinct after a reload.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeDeserializeMultipleOwnershipPerBundle, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    dataObj[TEST_BUNDLE_NAME].version = 3;
    dataObj[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    dataObj[TEST_BUNDLE_NAME].policyNames.push_back("second_policy_name");
    ManagedBrowserPolicyOwnership first;
    first.adminBundleName = "com.admin.a";
    first.isForceOverride = false;
    dataObj[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = first;
    ManagedBrowserPolicyOwnership second;
    second.adminBundleName = "com.admin.b";
    second.isForceOverride = true;
    dataObj[TEST_BUNDLE_NAME].ownership["second_policy_name"] = second;

    std::string policyData;
    ASSERT_TRUE(serializer->Serialize(dataObj, policyData));
    std::map<std::string, ManagedBrowserPolicyType> result;
    ASSERT_TRUE(serializer->Deserialize(policyData, result));
    ASSERT_EQ(result[TEST_BUNDLE_NAME].ownership.size(), 2);
    EXPECT_EQ(result[TEST_BUNDLE_NAME].version, 3);
    EXPECT_EQ(result[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, "com.admin.a");
    EXPECT_FALSE(result[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
    EXPECT_EQ(result[TEST_BUNDLE_NAME].ownership["second_policy_name"].adminBundleName, "com.admin.b");
    EXPECT_TRUE(result[TEST_BUNDLE_NAME].ownership["second_policy_name"].isForceOverride);
}

/**
 * @tc.name: TestSerializeDeserializeOwnershipAcrossBundles
 * @tc.desc: Ownership is stored per bundle and does not leak between bundles, so an owner of
 *           one bundle never blocks another bundle.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeDeserializeOwnershipAcrossBundles, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    dataObj[TEST_BUNDLE_NAME].version = 1;
    dataObj[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = "com.admin.a";
    owner.isForceOverride = true;
    dataObj[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = owner;
    dataObj["other_bundle_name"].version = 2;
    dataObj["other_bundle_name"].policyNames.push_back(TEST_POLICY_NAME);

    std::string policyData;
    ASSERT_TRUE(serializer->Serialize(dataObj, policyData));
    std::map<std::string, ManagedBrowserPolicyType> result;
    ASSERT_TRUE(serializer->Deserialize(policyData, result));
    ASSERT_EQ(result[TEST_BUNDLE_NAME].ownership.size(), 1);
    EXPECT_TRUE(result["other_bundle_name"].ownership.empty());
}

/**
 * @tc.name: TestDeserializeOwnershipOnlyTouchesBundlePresentInBlob
 * @tc.desc: Ownership of a bundle that is absent from the blob is left untouched, so
 *           merging blobs for different bundles does not drop unrelated ownership records.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeOwnershipOnlyTouchesBundlePresentInBlob,
    TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    ManagedBrowserPolicyOwnership stale;
    stale.adminBundleName = "com.admin.stale";
    stale.isForceOverride = true;

    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    dataObj["other_bundle_name"].ownership[TEST_POLICY_NAME] = stale;
    dataObj[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = stale;

    ASSERT_TRUE(serializer->Deserialize(TEST_POLICY_DATA, dataObj));
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].policyNames.size(), 1);
    EXPECT_EQ(dataObj["other_bundle_name"].ownership[TEST_POLICY_NAME].adminBundleName, "com.admin.stale");
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, "com.admin.stale");
}

/**
 * @tc.name: TestSerializeEmptyMap
 * @tc.desc: An empty map serializes to an empty JSON object and stays stable.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeEmptyMap, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    std::string policyData;
    ASSERT_TRUE(serializer->Serialize(dataObj, policyData));
    EXPECT_EQ(policyData, "{}");

    std::map<std::string, ManagedBrowserPolicyType> result;
    ASSERT_TRUE(serializer->Deserialize(policyData, result));
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: TestDeserializeFailWithMalformedPolicyNames
 * @tc.desc: A policyNames value that is not an array fails the whole blob, as before the
 *           ownership field was added.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeFailWithMalformedPolicyNames, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":\"test_policy_name\"}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    EXPECT_FALSE(serializer->Deserialize(policy, dataObj));
}

/**
 * @tc.name: TestDeserializeFailWithNonStringPolicyNameEntry
 * @tc.desc: A numeric entry inside policyNames fails the blob, so the policy list never
 *           contains a value that was not written as a policy name.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeFailWithNonStringPolicyNameEntry, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[123]}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    EXPECT_FALSE(serializer->Deserialize(policy, dataObj));
}

/**
 * @tc.name: TestDeserializeFailWithMissingVersion
 * @tc.desc: A missing version fails the blob so the merged view version is never guessed.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeFailWithMissingVersion, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"policyNames\":[\"test_policy_name\"]}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    EXPECT_FALSE(serializer->Deserialize(policy, dataObj));
}

/**
 * @tc.name: TestDeserializeKeepsOwnershipEntryWithEmptyName
 * @tc.desc: An ownership entry whose key is an empty string is deserialized like any other
 *           entry, because the key of the ownership map is the name of the policy and an
 *           empty name is a name that can never be looked up by a policy request.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeKeepsOwnershipEntryWithEmptyName, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":{\"test_policy_name\":{\"adminBundleName\":\"com.admin.a\",\"isForceOverride\":true},"
        "\"\":{\"adminBundleName\":\"com.admin.b\",\"isForceOverride\":true}}}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].ownership.size(), 2);
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].ownership.count(TEST_POLICY_NAME), 1);
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, "com.admin.a");
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].ownership.count(""), 1);
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].ownership[""].adminBundleName, "com.admin.b");
    EXPECT_TRUE(dataObj[TEST_BUNDLE_NAME].ownership[""].isForceOverride);
}

/**
 * @tc.name: TestDeserializeKeepsOwnershipWithEmptyAdminName
 * @tc.desc: An ownership record with an empty admin name is kept as it is, so a force
 *           override that was applied without a known identity is not silently dropped and
 *           the item stays protected.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeKeepsOwnershipWithEmptyAdminName, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":{\"test_policy_name\":{\"adminBundleName\":\"\",\"isForceOverride\":true}}}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    ASSERT_EQ(dataObj[TEST_BUNDLE_NAME].ownership.size(), 1);
    EXPECT_TRUE(dataObj[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName.empty());
    EXPECT_TRUE(dataObj[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
}

/**
 * @tc.name: TestSerializeDeserializeOwnershipOfSeveralBundles
 * @tc.desc: The ownership of several bundles is persisted independently, so the owner of one
 *           bundle never leaks into the ownership of another bundle.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeDeserializeOwnershipOfSeveralBundles, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    dataObj[TEST_BUNDLE_NAME].version = 1;
    dataObj[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership firstOwner;
    firstOwner.adminBundleName = "com.admin.a";
    firstOwner.isForceOverride = true;
    dataObj[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME] = firstOwner;
    dataObj["other_bundle_name"].version = 1;
    dataObj["other_bundle_name"].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership secondOwner;
    secondOwner.adminBundleName = "com.admin.b";
    secondOwner.isForceOverride = false;
    dataObj["other_bundle_name"].ownership[TEST_POLICY_NAME] = secondOwner;

    std::string policyData;
    ASSERT_TRUE(serializer->Serialize(dataObj, policyData));
    std::map<std::string, ManagedBrowserPolicyType> result;
    ASSERT_TRUE(serializer->Deserialize(policyData, result));
    ASSERT_EQ(result[TEST_BUNDLE_NAME].ownership.size(), 1);
    ASSERT_EQ(result["other_bundle_name"].ownership.size(), 1);
    EXPECT_EQ(result[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, "com.admin.a");
    EXPECT_EQ(result["other_bundle_name"].ownership[TEST_POLICY_NAME].adminBundleName, "com.admin.b");
}

/**
 * @tc.name: TestSerializeDeserializeOwnershipWithoutListedPolicy
 * @tc.desc: An ownership record of a policy that the bundle does not list is still persisted,
 *           so the ownership information is not lost when the policy list is rebuilt later.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestSerializeDeserializeOwnershipWithoutListedPolicy, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    dataObj[TEST_BUNDLE_NAME].version = 1;
    dataObj[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    ManagedBrowserPolicyOwnership owner;
    owner.adminBundleName = "com.admin.a";
    owner.isForceOverride = true;
    dataObj[TEST_BUNDLE_NAME].ownership["other_policy_name"] = owner;

    std::string policyData;
    ASSERT_TRUE(serializer->Serialize(dataObj, policyData));
    std::map<std::string, ManagedBrowserPolicyType> result;
    ASSERT_TRUE(serializer->Deserialize(policyData, result));
    ASSERT_EQ(result[TEST_BUNDLE_NAME].ownership.size(), 1);
    EXPECT_EQ(result[TEST_BUNDLE_NAME].ownership.count("other_policy_name"), 1);
    EXPECT_EQ(result[TEST_BUNDLE_NAME].ownership["other_policy_name"].adminBundleName, "com.admin.a");
}

/**
 * @tc.name: TestDeserializeToleratesOwnershipOfNonObjectEntry
 * @tc.desc: An ownership entry that is not an object is skipped, so one malformed record does
 *           not discard the ownership of the other policies of the same bundle.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeToleratesOwnershipOfNonObjectEntry, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"],"
        "\"ownership\":{\"good_policy\":{\"adminBundleName\":\"com.admin.a\",\"isForceOverride\":true},"
        "\"bad_policy\":\"com.admin.b\"}}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].ownership.size(), 1);
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].ownership.count("good_policy"), 1);
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].ownership.count("bad_policy"), 0);
}

/**
 * @tc.name: TestDeserializeOwnershipIsIndependentOfPolicyNames
 * @tc.desc: The ownership map is filled independently of the policy list, so a bundle whose
 *           policy list is empty can still carry an ownership record.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicySerializerTest, TestDeserializeOwnershipIsIndependentOfPolicyNames, TestSize.Level1)
{
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    const std::string policy = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[],"
        "\"ownership\":{\"test_policy_name\":{\"adminBundleName\":\"com.admin.a\",\"isForceOverride\":false}}}}";
    std::map<std::string, ManagedBrowserPolicyType> dataObj;
    ASSERT_TRUE(serializer->Deserialize(policy, dataObj));
    EXPECT_TRUE(dataObj[TEST_BUNDLE_NAME].policyNames.empty());
    ASSERT_EQ(dataObj[TEST_BUNDLE_NAME].ownership.size(), 1);
    EXPECT_EQ(dataObj[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].adminBundleName, "com.admin.a");
    EXPECT_FALSE(dataObj[TEST_BUNDLE_NAME].ownership[TEST_POLICY_NAME].isForceOverride);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS