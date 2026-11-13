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

#include "uint_serializer.h"

#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class UIntSerializerTest : public testing::Test {};

/**
 * @tc.name: TestDeserializeNormal
 * @tc.desc: Test UIntSerializer::Deserialize with a valid unsigned decimal string.
 * @tc.type: FUNC
 */
HWTEST_F(UIntSerializerTest, TestDeserializeNormal, TestSize.Level1)
{
    auto serializer = UIntSerializer::GetInstance();
    uint32_t dataObj = 0;
    EXPECT_TRUE(serializer->Deserialize("4294967295", dataObj));
    EXPECT_EQ(dataObj, 4294967295u);

    EXPECT_TRUE(serializer->Deserialize("0", dataObj));
    EXPECT_EQ(dataObj, 0u);
}

/**
 * @tc.name: TestDeserializeEmpty
 * @tc.desc: Test UIntSerializer::Deserialize resets the output on an empty string.
 * @tc.type: FUNC
 */
HWTEST_F(UIntSerializerTest, TestDeserializeEmpty, TestSize.Level1)
{
    auto serializer = UIntSerializer::GetInstance();
    uint32_t dataObj = 9;
    EXPECT_TRUE(serializer->Deserialize("", dataObj));
    EXPECT_EQ(dataObj, 0u);
}

/**
 * @tc.name: TestDeserializeInvalid
 * @tc.desc: Test UIntSerializer::Deserialize rejects negative, non-numeric and trailing input.
 * @tc.type: FUNC
 */
HWTEST_F(UIntSerializerTest, TestDeserializeInvalid, TestSize.Level1)
{
    auto serializer = UIntSerializer::GetInstance();
    uint32_t dataObj = 0;
    EXPECT_FALSE(serializer->Deserialize("-1", dataObj));
    EXPECT_FALSE(serializer->Deserialize("abc", dataObj));
    EXPECT_FALSE(serializer->Deserialize("12abc", dataObj));
    EXPECT_FALSE(serializer->Deserialize("4294967296", dataObj));
}

/**
 * @tc.name: TestSerialize
 * @tc.desc: Test UIntSerializer::Serialize writes the decimal form.
 * @tc.type: FUNC
 */
HWTEST_F(UIntSerializerTest, TestSerialize, TestSize.Level1)
{
    auto serializer = UIntSerializer::GetInstance();
    std::string jsonString;
    EXPECT_TRUE(serializer->Serialize(1024u, jsonString));
    EXPECT_EQ(jsonString, "1024");
}

/**
 * @tc.name: TestGetPolicyAndWritePolicy
 * @tc.desc: Test UIntSerializer reads a Uint32 from data and writes it back into reply.
 * @tc.type: FUNC
 */
HWTEST_F(UIntSerializerTest, TestGetPolicyAndWritePolicy, TestSize.Level1)
{
    auto serializer = UIntSerializer::GetInstance();
    MessageParcel data;
    data.WriteUint32(65535u);
    uint32_t result = 0;
    EXPECT_TRUE(serializer->GetPolicy(data, result));
    EXPECT_EQ(result, 65535u);

    MessageParcel reply;
    EXPECT_TRUE(serializer->WritePolicy(reply, result));
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadUint32(), 65535u);
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test UIntSerializer::MergePolicy keeps the last non-zero value.
 * @tc.type: FUNC
 */
HWTEST_F(UIntSerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = UIntSerializer::GetInstance();
    std::vector<uint32_t> data = { 0u, 7u, 0u, 8u };
    uint32_t result = 0u;
    EXPECT_TRUE(serializer->MergePolicy(data, result));
    EXPECT_EQ(result, 8u);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
