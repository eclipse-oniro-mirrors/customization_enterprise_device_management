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

#include "bit_serializer.h"

#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class BitSerializerTest : public testing::Test {};

/**
 * @tc.name: TestMergePolicyOrAllBits
 * @tc.desc: Test BitSerializer::MergePolicy OR-merges every item into the result.
 * @tc.type: FUNC
 */
HWTEST_F(BitSerializerTest, TestMergePolicyOrAllBits, TestSize.Level1)
{
    BitSerializer serializer;
    std::vector<uint32_t> data = { 0x1u, 0x4u, 0x8u };
    uint32_t result = 0u;
    EXPECT_TRUE(serializer.MergePolicy(data, result));
    EXPECT_EQ(result, 0xDu);
}

/**
 * @tc.name: TestMergePolicyKeepsExistingBits
 * @tc.desc: Test BitSerializer::MergePolicy keeps the bits already set in the result.
 * @tc.type: FUNC
 */
HWTEST_F(BitSerializerTest, TestMergePolicyKeepsExistingBits, TestSize.Level1)
{
    BitSerializer serializer;
    std::vector<uint32_t> data = { 0x2u };
    uint32_t result = 0x10u;
    EXPECT_TRUE(serializer.MergePolicy(data, result));
    EXPECT_EQ(result, 0x12u);
}

/**
 * @tc.name: TestMergePolicyEmpty
 * @tc.desc: Test BitSerializer::MergePolicy leaves the result untouched for an empty list.
 * @tc.type: FUNC
 */
HWTEST_F(BitSerializerTest, TestMergePolicyEmpty, TestSize.Level1)
{
    BitSerializer serializer;
    std::vector<uint32_t> data;
    uint32_t result = 0x7u;
    EXPECT_TRUE(serializer.MergePolicy(data, result));
    EXPECT_EQ(result, 0x7u);
}

/**
 * @tc.name: TestMergePolicyDiffersFromBase
 * @tc.desc: Test BitSerializer::MergePolicy accumulates bits instead of keeping the last value.
 * @tc.type: FUNC
 */
HWTEST_F(BitSerializerTest, TestMergePolicyDiffersFromBase, TestSize.Level1)
{
    BitSerializer serializer;
    std::vector<uint32_t> data = { 0x1u, 0x2u, 0u };
    uint32_t result = 0u;
    EXPECT_TRUE(serializer.MergePolicy(data, result));
    EXPECT_EQ(result, 0x3u);
}

/**
 * @tc.name: TestInheritedDeserializeAndSerialize
 * @tc.desc: Test BitSerializer keeps the UIntSerializer parse behaviour.
 * @tc.type: FUNC
 */
HWTEST_F(BitSerializerTest, TestInheritedDeserializeAndSerialize, TestSize.Level1)
{
    BitSerializer serializer;
    uint32_t dataObj = 0;
    EXPECT_TRUE(serializer.Deserialize("15", dataObj));
    EXPECT_EQ(dataObj, 15u);
    EXPECT_FALSE(serializer.Deserialize("abc", dataObj));

    std::string jsonString;
    EXPECT_TRUE(serializer.Serialize(15u, jsonString));
    EXPECT_EQ(jsonString, "15");
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
