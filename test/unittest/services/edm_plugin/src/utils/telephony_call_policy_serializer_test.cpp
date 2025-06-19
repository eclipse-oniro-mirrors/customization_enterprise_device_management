/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "telephony_call_policy_serializer_test.h"
#include "edm_constants.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void TelephonyCallPolicySerializerTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void TelephonyCallPolicySerializerTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSerializeEmpty
 * @tc.desc: Test TelephonyCallPolicySerializerTest::Serialize when jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyCallPolicySerializerTest, TestSerializeEmpty, TestSize.Level1)
{
    auto serializer = TelephonyCallPolicySerializer::GetInstance();
    std::string jsonString;
    std::map<std::string, TelephonyCallPolicyType> dataObj;
    bool ret = serializer->Serialize(dataObj, jsonString);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestSerializeSuc
 * @tc.desc: Test TelephonyCallPolicySerializerTest::Serialize
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyCallPolicySerializerTest, TestSerializeSuc, TestSize.Level1)
{
    auto serializer = TelephonyCallPolicySerializer::GetInstance();
    std::string jsonString;
    std::map<std::string, TelephonyCallPolicyType> dataObj;
    TelephonyCallPolicyType info;
    info.policyFlag = 0;
    info.numberList.push_back("111111");
    dataObj["incoming"] = info;
    bool ret = serializer->Serialize(dataObj, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(jsonString.empty());
}

/**
 * @tc.name: TestDeserializeWithEmptyString
 * @tc.desc: Test TelephonyCallPolicySerializerTest::Deserialize jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyCallPolicySerializerTest, TestDeserializeWithEmptyString, TestSize.Level1)
{
    auto serializer = TelephonyCallPolicySerializer::GetInstance();
    std::string jsonString = "";
    std::map<std::string, TelephonyCallPolicyType> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestDeserializeRootIsNotArray
 * @tc.desc: Test TelephonyCallPolicySerializerTest::Deserialize RootIsNotArray
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyCallPolicySerializerTest, TestDeserializeRootIsNotArray, TestSize.Level1)
{
    auto serializer = TelephonyCallPolicySerializer::GetInstance();
    std::string jsonString = R"({"key": "value"})";
    std::map<std::string, TelephonyCallPolicyType> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestDeserializeSuc
 * @tc.desc: Test TelephonyCallPolicySerializerTest::Deserialize
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyCallPolicySerializerTest, TestDeserializeSuc, TestSize.Level1)
{
    auto serializer = TelephonyCallPolicySerializer::GetInstance();
    std::string jsonString = R"({"incoming":{"policyFlag":0,"numberList":["11111111"]}})";
    std::map<std::string, TelephonyCallPolicyType> dataObj;
    bool ret = serializer->Deserialize(jsonString, dataObj);
    ASSERT_TRUE(ret);
    ASSERT_EQ(dataObj.size(), 1);
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test TelephonyCallPolicySerializerTest::MergePolicy
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyCallPolicySerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = TelephonyCallPolicySerializer::GetInstance();
    std::vector<std::map<std::string, TelephonyCallPolicyType>> dataObj;
    std::map<std::string, TelephonyCallPolicyType> data;
    TelephonyCallPolicyType info;
    info.policyFlag = 0;
    info.numberList.push_back("111111");
    data["incoming"] = info;
    dataObj.push_back(data);
    std::map<std::string, TelephonyCallPolicyType> result;
    serializer->MergePolicy(dataObj, result);
    ASSERT_TRUE(result.size() == 1);
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test TelephonyCallPolicySerializerTest::MergePolicy
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyCallPolicySerializerTest, TestMergePolicy002, TestSize.Level1)
{
    auto serializer = TelephonyCallPolicySerializer::GetInstance();
    std::vector<std::map<std::string, TelephonyCallPolicyType>> dataObj;
    std::map<std::string, TelephonyCallPolicyType> data;
    TelephonyCallPolicyType info;
    info.policyFlag = 0;
    info.numberList.push_back("111111");
    data["incoming"] = info;
    dataObj.push_back(data);
    std::map<std::string, TelephonyCallPolicyType> result;
    result["incoming"] = info;
    serializer->MergePolicy(dataObj, result);
    ASSERT_TRUE(result.size() == 1);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS