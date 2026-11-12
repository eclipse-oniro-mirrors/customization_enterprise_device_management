/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "allowed_notification_bundles_serializer.h"

#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
const std::string VALID_POLICY = "[{\"userId\":100,\"trustList\":[\"com.test.a\",\"com.test.b\"]}]";
const std::string NO_TRUST_LIST_POLICY = "[{\"userId\":100}]";
const std::string NO_USER_ID_POLICY = "[{\"trustList\":[\"com.test.a\"]}]";
const std::string BROKEN_POLICY = "[{\"userId\":\"100\",\"trustList\":[]}]";
}

class AllowedNotificationBundlesSerializerTest : public testing::Test {};

/**
 * @tc.name: TestDeserializeValid
 * @tc.desc: Test AllowedNotificationBundlesSerializer::Deserialize parses userId and trustList.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesSerializerTest, TestDeserializeValid, TestSize.Level1)
{
    auto serializer = AllowedNotificationBundlesSerializer::GetInstance();
    std::vector<AllowedNotificationBundlesType> dataObj;
    EXPECT_TRUE(serializer->Deserialize(VALID_POLICY, dataObj));
    ASSERT_EQ(dataObj.size(), 1u);
    EXPECT_EQ(dataObj[0].userId, 100);
    ASSERT_EQ(dataObj[0].trustList.size(), 2u);
    EXPECT_TRUE(dataObj[0].trustList.count("com.test.a") == 1);
    EXPECT_TRUE(dataObj[0].trustList.count("com.test.b") == 1);
}

/**
 * @tc.name: TestDeserializeEmpty
 * @tc.desc: Test AllowedNotificationBundlesSerializer::Deserialize accepts an empty policy.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesSerializerTest, TestDeserializeEmpty, TestSize.Level1)
{
    auto serializer = AllowedNotificationBundlesSerializer::GetInstance();
    std::vector<AllowedNotificationBundlesType> dataObj;
    EXPECT_TRUE(serializer->Deserialize("", dataObj));
    EXPECT_TRUE(dataObj.empty());
}

/**
 * @tc.name: TestDeserializeInvalid
 * @tc.desc: Test AllowedNotificationBundlesSerializer::Deserialize rejects malformed items.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesSerializerTest, TestDeserializeInvalid, TestSize.Level1)
{
    auto serializer = AllowedNotificationBundlesSerializer::GetInstance();
    std::vector<AllowedNotificationBundlesType> dataObj;
    EXPECT_FALSE(serializer->Deserialize("not-a-json", dataObj));
    EXPECT_FALSE(serializer->Deserialize(NO_TRUST_LIST_POLICY, dataObj));
    EXPECT_FALSE(serializer->Deserialize(NO_USER_ID_POLICY, dataObj));
    EXPECT_FALSE(serializer->Deserialize(BROKEN_POLICY, dataObj));
}

/**
 * @tc.name: TestSerializeRoundTrip
 * @tc.desc: Test AllowedNotificationBundlesSerializer::Serialize writes parsable JSON.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesSerializerTest, TestSerializeRoundTrip, TestSize.Level1)
{
    auto serializer = AllowedNotificationBundlesSerializer::GetInstance();
    AllowedNotificationBundlesType item;
    item.userId = 101;
    item.trustList.insert("com.test.c");
    std::vector<AllowedNotificationBundlesType> dataObj = { item };

    std::string policy;
    EXPECT_TRUE(serializer->Serialize(dataObj, policy));
    EXPECT_FALSE(policy.empty());

    std::vector<AllowedNotificationBundlesType> parsed;
    EXPECT_TRUE(serializer->Deserialize(policy, parsed));
    ASSERT_EQ(parsed.size(), 1u);
    EXPECT_EQ(parsed[0].userId, 101);
    EXPECT_TRUE(parsed[0].trustList.count("com.test.c") == 1);
}

/**
 * @tc.name: TestSerializeEmpty
 * @tc.desc: Test AllowedNotificationBundlesSerializer::Serialize keeps policy for an empty list.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesSerializerTest, TestSerializeEmpty, TestSize.Level1)
{
    auto serializer = AllowedNotificationBundlesSerializer::GetInstance();
    std::vector<AllowedNotificationBundlesType> dataObj;
    std::string policy = "unset";
    EXPECT_TRUE(serializer->Serialize(dataObj, policy));
    EXPECT_EQ(policy, "unset");
}

/**
 * @tc.name: TestGetPolicy
 * @tc.desc: Test AllowedNotificationBundlesSerializer::GetPolicy reads the trust list then userId.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesSerializerTest, TestGetPolicy, TestSize.Level1)
{
    auto serializer = AllowedNotificationBundlesSerializer::GetInstance();
    MessageParcel data;
    std::vector<std::string> trustList = { "com.test.a", "com.test.b" };
    data.WriteStringVector(trustList);
    data.WriteInt32(100);

    std::vector<AllowedNotificationBundlesType> result;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].userId, 100);
    ASSERT_EQ(result[0].trustList.size(), 2u);
}

/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test AllowedNotificationBundlesSerializer::WritePolicy returns success.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesSerializerTest, TestWritePolicy, TestSize.Level1)
{
    auto serializer = AllowedNotificationBundlesSerializer::GetInstance();
    MessageParcel reply;
    std::vector<AllowedNotificationBundlesType> result;
    EXPECT_TRUE(serializer->WritePolicy(reply, result));
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test AllowedNotificationBundlesSerializer::MergePolicy unions trust lists per userId.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesSerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = AllowedNotificationBundlesSerializer::GetInstance();
    AllowedNotificationBundlesType first;
    first.userId = 100;
    first.trustList.insert("com.test.a");
    AllowedNotificationBundlesType second;
    second.userId = 100;
    second.trustList.insert("com.test.b");
    AllowedNotificationBundlesType other;
    other.userId = 101;
    other.trustList.insert("com.test.c");

    std::vector<std::vector<AllowedNotificationBundlesType>> data = {
        { first, second },
        { other },
    };
    std::vector<AllowedNotificationBundlesType> result;
    EXPECT_TRUE(serializer->MergePolicy(data, result));
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].userId, 100);
    ASSERT_EQ(result[0].trustList.size(), 2u);
    EXPECT_EQ(result[1].userId, 101);

    std::vector<std::vector<AllowedNotificationBundlesType>> emptyData;
    std::vector<AllowedNotificationBundlesType> untouched = { first };
    EXPECT_TRUE(serializer->MergePolicy(emptyData, untouched));
    ASSERT_EQ(untouched.size(), 1u);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
