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

#include "clipboard_info.h"
#include "clipboard_policy_serializer_test.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string POLICY_DATA_ILLEGAL = "[{\"tokenId\":\"tokenId\",\"clipboardPolicy\":1},{\"clipboardPolicy\":2}]";
const std::string POLICY_DATA_ILLEGAL2 = "[{\"tokenId\":1,\"clipboardPolicy\":\"clipboardPolicy\"},{\"tokenId\":2}]";
const std::string POLICY_DATA_ILLEGAL3 = "[{\"tokenId\":2,\"userId\":\"userId\",\"bundleName\":\"com.ohos.test1\","
    "\"clipboardPolicy\":1},{\"bundleName\":\"com.ohos.test1\",\"clipboardPolicy\":2}]";
const std::string POLICY_DATA1 = "[{\"tokenId\":1,\"clipboardPolicy\":3},{\"tokenId\":2,\"clipboardPolicy\":0}]";
const std::string POLICY_DATA2 = "[{\"tokenId\":1,\"userId\":100,\"bundleName\":\"com.ohos.test1\","
    "\"clipboardPolicy\":3},{\"tokenId\":2,\"userId\":101,\"bundleName\":\"com.ohos.test2\",\"clipboardPolicy\":0}]";
void ClipboardPolicySerializerTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ClipboardPolicySerializerTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDeserializeEmpty
 * @tc.desc: Test ClipboardSerializer::Deserialize when jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicySerializerTest, TestDeserializeEmpty, TestSize.Level1)
{
    auto serializer = ClipboardSerializer::GetInstance();
    std::string jsonString;
    std::map<int32_t, ClipboardInfo> result;
    bool ret = serializer->Deserialize(jsonString, result);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(result.empty());
}

/**
 * @tc.name: TestDeserializeIllegal
 * @tc.desc: Test ClipboardSerializer::Deserialize when jsonString is illegal
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicySerializerTest, TestDeserializeIllegal, TestSize.Level1)
{
    auto serializer = ClipboardSerializer::GetInstance();
    std::string jsonString = POLICY_DATA_ILLEGAL;
    std::map<int32_t, ClipboardInfo> result;
    bool ret = serializer->Deserialize(jsonString, result);
    ASSERT_FALSE(ret);
    ASSERT_TRUE(result.empty());
}

/**
 * @tc.name: TestDeserializeIllegal2
 * @tc.desc: Test ClipboardSerializer::Deserialize when jsonString is illegal
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicySerializerTest, TestDeserializeIllegal2, TestSize.Level1)
{
    auto serializer = ClipboardSerializer::GetInstance();
    std::string jsonString = POLICY_DATA_ILLEGAL2;
    std::map<int32_t, ClipboardInfo> result;
    bool ret = serializer->Deserialize(jsonString, result);
    ASSERT_FALSE(ret);
    ASSERT_TRUE(result.empty());
}

/**
 * @tc.name: TestDeserializeSuc
 * @tc.desc: Test ClipboardSerializer::Deserialize
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicySerializerTest, TestDeserializeSuc, TestSize.Level1)
{
    auto serializer = ClipboardSerializer::GetInstance();
    std::string jsonString = POLICY_DATA;
    std::map<int32_t, ClipboardInfo> result;
    bool ret = serializer->Deserialize(jsonString, result);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(result.size() == 2);
}

/**
 * @tc.name: TestSerializeEmpty
 * @tc.desc: Test ClipboardSerializer::Serialize
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicySerializerTest, TestSerializeEmpty, TestSize.Level1)
{
    auto serializer = ClipboardSerializer::GetInstance();
    std::string jsonString;
    std::map<int32_t, ClipboardInfo> result;
    bool ret = serializer->Serialize(result, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(jsonString.empty());
}

/**
 * @tc.name: TestSerializeSuc
 * @tc.desc: Test ClipboardSerializer::Serialize
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicySerializerTest, TestSerializeSuc, TestSize.Level1)
{
    auto serializer = ClipboardSerializer::GetInstance();
    std::string jsonString;
    std::map<int32_t, ClipboardInfo> result;
    ClipboardInfo info = {ClipboardPolicy::IN_APP, -1, ""};
    result.insert(std::make_pair(1, info));
    bool ret = serializer->Serialize(result, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(jsonString.empty());
}

/**
 * @tc.name: TestGetPolicySuc
 * @tc.desc: Test ClipboardSerializer::GetPolicy
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicySerializerTest, TestGetPolicySuc, TestSize.Level1)
{
    auto serializer = ClipboardSerializer::GetInstance();
    MessageParcel data;
    data.WriteInt32(1);
    data.WriteInt32(537098750);
    data.WriteInt32(3);
    std::map<int32_t, ClipboardInfo> result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(result.size() == 1);
}

/**
 * @tc.name: TestWritePolicySuc
 * @tc.desc: Test ClipboardSerializer::WritePolicy
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicySerializerTest, TestWritePolicySuc, TestSize.Level1)
{
    auto serializer = ClipboardSerializer::GetInstance();
    MessageParcel reply;
    std::map<int32_t, ClipboardInfo> result;
    bool ret = serializer->WritePolicy(reply, result);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestMergePolicySuc
 * @tc.desc: Test ClipboardSerializer::MergePolicy
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardPolicySerializerTest, TestMergePolicySuc, TestSize.Level1)
{
    auto serializer = ClipboardSerializer::GetInstance();
    std::vector<std::map<int32_t, ClipboardInfo>> data;
    std::map<int32_t, ClipboardInfo> result;
    data.push_back(result);
    bool ret = serializer->MergePolicy(data, result);
    ASSERT_TRUE(ret);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS