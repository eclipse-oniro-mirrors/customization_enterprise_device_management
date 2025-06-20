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

/**
 * @tc.name: TestSetDifferencePolicyData001
 * @tc.desc: Test ArrayIntSerializerTest::SetDifferencePolicyData when data is empty
 * @tc.type: FUNC
 */
HWTEST_F(ArrayIntSerializerTest, TestSetDifferencePolicyData001, TestSize.Level1)
{
    auto serializer = ArrayIntSerializer::GetInstance();
    std::vector<int32_t> data;
    std::vector<int32_t> currentData;
    std::vector<int32_t> res = serializer->SetDifferencePolicyData(data, currentData);
    ASSERT_TRUE(res.empty());
}

/**
 * @tc.name: TestSetDifferencePolicyData002
 * @tc.desc: Test ArrayIntSerializerTest::SetDifferencePolicyData func
 * @tc.type: FUNC
 */
HWTEST_F(ArrayIntSerializerTest, TestSetDifferencePolicyData002, TestSize.Level1)
{
    auto serializer = ArrayIntSerializer::GetInstance();
    std::vector<int32_t> data;
    data.push_back(1);
    data.push_back(2);
    std::vector<int32_t> currentData;
    currentData.push_back(2);
    currentData.push_back(3);
    std::vector<int32_t> res = serializer->SetDifferencePolicyData(data, currentData);
    ASSERT_TRUE(res.size() == 1);
}

/**
 * @tc.name: TestSetUnionPolicyData001
 * @tc.desc: Test ArrayIntSerializerTest::SetUnionPolicyData when data is empty
 * @tc.type: FUNC
 */
HWTEST_F(ArrayIntSerializerTest, TestSetUnionPolicyData001, TestSize.Level1)
{
    auto serializer = ArrayIntSerializer::GetInstance();
    std::vector<int32_t> data;
    std::vector<int32_t> currentData;
    std::vector<int32_t> res = serializer->SetUnionPolicyData(data, currentData);
    ASSERT_TRUE(res.empty());
}

/**
 * @tc.name: TestSetUnionPolicyData002
 * @tc.desc: Test ArrayIntSerializerTest::SetUnionPolicyData func
 * @tc.type: FUNC
 */
HWTEST_F(ArrayIntSerializerTest, TestSetUnionPolicyData002, TestSize.Level1)
{
    auto serializer = ArrayIntSerializer::GetInstance();
    std::vector<int32_t> data;
    data.push_back(1);
    data.push_back(2);
    std::vector<int32_t> currentData;
    currentData.push_back(2);
    currentData.push_back(3);
    std::vector<int32_t> res = serializer->SetUnionPolicyData(data, currentData);
    ASSERT_TRUE(res.size() == 3);
}

/**
 * @tc.name: TestSerialize001
 * @tc.desc: Test ArrayIntSerializerTest::Serialize when jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(ArrayIntSerializerTest, TestSerialize001, TestSize.Level1)
{
    auto serializer = ArrayIntSerializer::GetInstance();
    std::string jsonString;
    std::vector<int32_t> dataObj;
    bool ret = serializer->Serialize(dataObj, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(jsonString.empty());
}

/**
 * @tc.name: TestSerialize002
 * @tc.desc: Test ArrayIntSerializerTest::Serialize func
 * @tc.type: FUNC
 */
HWTEST_F(ArrayIntSerializerTest, TestSerialize002, TestSize.Level1)
{
    auto serializer = ArrayIntSerializer::GetInstance();
    std::string jsonString;
    std::vector<int32_t> data;
    data.push_back(1);
    data.push_back(2);
    bool ret = serializer->Serialize(data, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(jsonString.empty());
}

/**
 * @tc.name: TestDeserialize001
 * @tc.desc: Test ArrayIntSerializerTest::Deserialize when jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(ArrayIntSerializerTest, TestDeserialize001, TestSize.Level1)
{
    auto serializer = ArrayIntSerializer::GetInstance();
    std::string jsonString = "";
    std::vector<int32_t> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestDeserialize002
 * @tc.desc: Test ArrayIntSerializerTest::Deserialize RootIsNotArray
 * @tc.type: FUNC
 */
HWTEST_F(ArrayIntSerializerTest, TestDeserialize002, TestSize.Level1)
{
    auto serializer = ArrayIntSerializer::GetInstance();
    std::string jsonString = R"({"key": "value"})";
    std::vector<int32_t> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestDeserialize003
 * @tc.desc: Test ArrayIntSerializerTest::Deserialize func
 * @tc.type: FUNC
 */
HWTEST_F(ArrayIntSerializerTest, TestDeserialize003, TestSize.Level1)
{
    auto serializer = ArrayIntSerializer::GetInstance();
    std::string jsonString = R"([1])";
    std::vector<int32_t> dataObj;
    serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(dataObj.size() == 1);
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test ArrayIntSerializerTest::MergePolicy
 * @tc.type: FUNC
 */
HWTEST_F(ArrayIntSerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = ArrayIntSerializer::GetInstance();
    std::vector<std::vector<int32_t>> dataObj;
    std::vector<int32_t> data;
    data.push_back(1);
    dataObj.push_back(data);
    std::vector<int32_t> result;
    serializer->MergePolicy(dataObj, result);
    ASSERT_TRUE(result.size() == 1);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
