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

#include "array_int_serializer.h"

#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class ArrayIntSerializerTest : public testing::Test {};
/**
 * @tc.name: TestGetPolicy001
 * @tc.desc: Test ArrayIntSerializer::GetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayIntSerializerTest, TestGetPolicy001, TestSize.Level1)
{
    auto serializer = ArrayIntSerializer::GetInstance();
    MessageParcel data;
    std::vector<int32_t> inputData;
    inputData.push_back(1);
    inputData.push_back(2);
    data.WriteInt32Vector(inputData);

    std::vector<int32_t> outputData;
    bool ret = serializer->GetPolicy(data, outputData);
    ASSERT_TRUE(ret);
    EXPECT_TRUE(outputData.size() == 2);
}

/**
 * @tc.name: TestGetPolicy002
 * @tc.desc: Test ArrayIntSerializer::GetPolicy repeat data func.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayIntSerializerTest, TestGetPolicy002, TestSize.Level1)
{
    auto serializer = ArrayIntSerializer::GetInstance();
    MessageParcel data;
    std::vector<int32_t> inputData;
    inputData.push_back(2);
    inputData.push_back(2);
    data.WriteInt32Vector(inputData);

    std::vector<int32_t> outputData;
    bool ret = serializer->GetPolicy(data, outputData);
    ASSERT_TRUE(ret);
    EXPECT_TRUE(outputData.size() == 1);
}

/**
 * @tc.name: TestGetPolicy003
 * @tc.desc: Test ArrayIntSerializer::GetPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(ArrayIntSerializerTest, TestGetPolicy003, TestSize.Level1)
{
    auto serializer = ArrayIntSerializer::GetInstance();
    MessageParcel data;
    std::vector<std::string> inputData;
    data.WriteStringVector(inputData);

    std::vector<int32_t> outputData;
    serializer->GetPolicy(data, outputData);
    EXPECT_TRUE(outputData.size() == 0);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
