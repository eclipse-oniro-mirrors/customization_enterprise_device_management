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

#include "fingerprint_policy_serializer_test.h"
#include "edm_constants.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void FingerPrintPolicySerializerTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void FingerPrintPolicySerializerTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDeserializeInvalid
 * @tc.desc: Test FingerPrintPolicySerializer::Deserialize when jsonString is invalid
 * @tc.type: FUNC
 */
HWTEST_F(FingerPrintPolicySerializerTest, TestDeserializeInvalid, TestSize.Level1)
{
    auto serializer = FingerprintPolicySerializer::GetInstance();
    std::string invalidData = "invalid_json";
    FingerprintPolicy result;
    bool ret = serializer->Deserialize(invalidData, result);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestDeserializeTrue
 * @tc.desc: Test FingerPrintPolicySerializer::Deserialize when jsonString is "true"
 * @tc.type: FUNC
 */
HWTEST_F(FingerPrintPolicySerializerTest, TestDeserializeTrue, TestSize.Level1)
{
    auto serializer = FingerprintPolicySerializer::GetInstance();
    std::string boolDataTrue = "true";
    FingerprintPolicy result;
    bool ret = serializer->Deserialize(boolDataTrue, result);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(result.globalDisallow);
}

/**
 * @tc.name: TestDeserializeWithNumber
 * @tc.desc: Test FingerPrintPolicySerializer::Deserialize when jsonString has number
 * @tc.type: FUNC
 */
HWTEST_F(FingerPrintPolicySerializerTest, TestDeserializeWithNumber, TestSize.Level1)
{
    auto serializer = FingerprintPolicySerializer::GetInstance();
    std::string mixedData = "[1, 2, \"string\", true]";
    FingerprintPolicy result;
    bool ret = serializer->Deserialize(mixedData, result);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestSerialize
 * @tc.desc: Test FingerPrintPolicySerializer::Serialize
 * @tc.type: FUNC
 */
HWTEST_F(FingerPrintPolicySerializerTest, TestSerialize, TestSize.Level1)
{
    auto serializer = FingerprintPolicySerializer::GetInstance();
    std::string data;
    FingerprintPolicy result;
    result.globalDisallow = true;
    bool ret = serializer->Serialize(result, data);
    ASSERT_TRUE(ret);
    result.globalDisallow = false;
    ret = serializer->Serialize(result, data);
    ASSERT_TRUE(ret);
    result.accountIds.insert(0);
    ret = serializer->Serialize(result, data);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestGetPolicy
 * @tc.desc: Test FingerPrintPolicySerializer::GetPolicy
 * @tc.type: FUNC
 */
HWTEST_F(FingerPrintPolicySerializerTest, TestGetPolicy, TestSize.Level1)
{
    auto serializer = FingerprintPolicySerializer::GetInstance();
    MessageParcel data;
    FingerprintPolicy result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test FingerPrintPolicySerializer::WritePolicy
 * @tc.type: FUNC
 */
HWTEST_F(FingerPrintPolicySerializerTest, TestWritePolicy, TestSize.Level1)
{
    auto serializer = FingerprintPolicySerializer::GetInstance();
    MessageParcel data;
    FingerprintPolicy result;
    bool ret = serializer->WritePolicy(data, result);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestMergePolicy
 * @tc.desc: Test FingerPrintPolicySerializer::MergePolicy
 * @tc.type: FUNC
 */
HWTEST_F(FingerPrintPolicySerializerTest, TestMergePolicy, TestSize.Level1)
{
    auto serializer = FingerprintPolicySerializer::GetInstance();
    FingerprintPolicy result;
    std::vector<FingerprintPolicy> data;
    bool ret = serializer->MergePolicy(data, result);
    ASSERT_TRUE(ret);
    data.push_back(result);
    ret = serializer->MergePolicy(data, result);
    ASSERT_TRUE(ret);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS