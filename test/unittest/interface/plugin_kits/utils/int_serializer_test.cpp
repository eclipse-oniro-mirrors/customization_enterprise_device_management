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

#include "int_serializer.h"

#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class IntSerializerTest : public testing::Test {};

/**
 * @tc.name: TestDeserializeNormal
 * @tc.desc: Test IntSerializer::Deserialize with a valid decimal string.
 * @tc.type: FUNC
 */
HWTEST_F(IntSerializerTest, TestDeserializeNormal, TestSize.Level1)
{
    auto serializer = IntSerializer::GetInstance();
    int32_t dataObj = 0;
    EXPECT_TRUE(serializer->Deserialize("123", dataObj));
    EXPECT_EQ(dataObj, 123);

    int32_t negative = 0;
    EXPECT_TRUE(serializer->Deserialize("-456", negative));
    EXPECT_EQ(negative, -456);
}

/**
 * @tc.name: TestDeserializeEmpty
 * @tc.desc: Test IntSerializer::Deserialize resets the output on an empty string.
 * @tc.type: FUNC
 */
HWTEST_F(IntSerializerTest, TestDeserializeEmpty, TestSize.Level1)
{
    auto serializer = IntSerializer::GetInstance();
    int32_t dataObj = 7;
    EXPECT_TRUE(serializer->Deserialize("", dataObj));
    EXPECT_EQ(dataObj, 0);
}

/**
 * @tc.name: TestDeserializeInvalid
 * @tc.desc: Test IntSerializer::Deserialize rejects non-numeric and truncated input.
 * @tc.type: FUNC
 */
HWTEST_F(IntSerializerTest, TestDeserializeInvalid, TestSize.Level1)
{
    auto serializer = IntSerializer::GetInstance();
    int32_t dataObj = 0;
    EXPECT_FALSE(serializer->Deserialize("abc", dataObj));
    EXPECT_FALSE(serializer->Deserialize("12abc", dataObj));
}

/**
 * @tc.name: TestSerialize
 * @tc.desc: Test IntSerializer::Serialize writes the decimal form.
 * @tc.type: FUNC
 */
HWTEST_F(IntSerializerTest, TestSerialize, TestSize.Level1)
{
    auto serializer = IntSerializer::GetInstance();
    std::string jsonString;
    EXPECT_TRUE(serializer->Serialize(2026, jsonString));
    EXPECT_EQ(jsonString, "2026");

    std::string zero;
    EXPECT_TRUE(serializer->Serialize(0, zero));
    EXPECT_EQ(zero, "0");
}

/**
 * @tc.name: TestGetPolicyAndWritePolicy
 * @tc.desc: Test IntSerializer reads an Int32 from data and writes it back into reply.
 * @tc.type: FUNC
 */
HWTEST_F(IntSerializerTest, TestGetPolicyAndWritePolicy, TestSize.Level1)
{
    auto serializer = IntSerializer::GetInstance();
    MessageParcel data;
    data.WriteInt32(88);
    int32_t result = 0;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
    EXPECT_EQ(result, 88);

    MessageParcel reply;
    EXPECT_TRUE(serializer->WritePolicy(reply, result));
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), 88);
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test IntSerializer::MergePolicy keeps the last non-zero value.
 * @tc.type: FUNC
 */
HWTEST_F(IntSerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = IntSerializer::GetInstance();
    std::vector<int32_t> data = { 0, 5, 0, 9 };
    int32_t result = 0;
    EXPECT_TRUE(serializer->MergePolicy(data, result));
    EXPECT_EQ(result, 9);

    std::vector<int32_t> allZero = { 0, 0 };
    int32_t keep = 3;
    EXPECT_TRUE(serializer->MergePolicy(allZero, keep));
    EXPECT_EQ(keep, 3);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
