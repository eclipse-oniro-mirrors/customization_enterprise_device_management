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

#include <gtest/gtest.h>

#include "switch_param_serializer.h"
#include "switch_param_serializer_test.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_JSON_EMPTY = "";
const std::string TEST_JSON_INVALID = "{123";
const std::string TEST_JSON_NOT_ARRAY = "{\"key\":\"BLUETOOTH\",\"status\":\"ON\"}";
const std::string TEST_JSON_VALID = "[{\"key\":\"BLUETOOTH\",\"status\":\"OFF\"}]";
const std::string TEST_JSON_MULTIPLE =
    "[{\"key\":\"BLUETOOTH\",\"status\":\"ON\"},{\"key\":\"WIFI\",\"status\":\"OFF\"}]";
const std::string TEST_JSON_FORCE_ON = "[{\"key\":\"BLUETOOTH\",\"status\":\"FORCE_ON\"}]";

void SwitchParamSerializerTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SwitchParamSerializerTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDeserializeEmpty
 * @tc.desc: Test SwitchParamSerializer::Deserialize when jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestDeserializeEmpty, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    std::vector<SwitchParam> config;
    bool ret = serializer->Deserialize(TEST_JSON_EMPTY, config);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(config.empty());
}

/**
 * @tc.name: TestDeserializeInvalidJson
 * @tc.desc: Test SwitchParamSerializer::Deserialize when jsonString is invalid
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestDeserializeInvalidJson, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    std::vector<SwitchParam> config;
    bool ret = serializer->Deserialize(TEST_JSON_INVALID, config);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestDeserializeNotArray
 * @tc.desc: Test SwitchParamSerializer::Deserialize when jsonString is not array
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestDeserializeNotArray, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    std::vector<SwitchParam> config;
    bool ret = serializer->Deserialize(TEST_JSON_NOT_ARRAY, config);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestDeserializeSuccess
 * @tc.desc: Test SwitchParamSerializer::Deserialize with valid json
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestDeserializeSuccess, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    std::vector<SwitchParam> config;
    bool ret = serializer->Deserialize(TEST_JSON_VALID, config);
    ASSERT_TRUE(ret);
    ASSERT_EQ(config.size(), 1);
    ASSERT_EQ(config[0].key, SwitchKey::BLUETOOTH);
    ASSERT_EQ(config[0].status, SwitchStatus::OFF);
}

/**
 * @tc.name: TestDeserializeMultipleItems
 * @tc.desc: Test SwitchParamSerializer::Deserialize with multiple items
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestDeserializeMultipleItems, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    std::vector<SwitchParam> config;
    bool ret = serializer->Deserialize(TEST_JSON_MULTIPLE, config);
    ASSERT_TRUE(ret);
    ASSERT_EQ(config.size(), 2);
    ASSERT_EQ(config[0].key, SwitchKey::BLUETOOTH);
    ASSERT_EQ(config[0].status, SwitchStatus::ON);
    ASSERT_EQ(config[1].key, SwitchKey::WIFI);
    ASSERT_EQ(config[1].status, SwitchStatus::OFF);
}

/**
 * @tc.name: TestDeserializeForceOn
 * @tc.desc: Test SwitchParamSerializer::Deserialize with FORCE_ON status
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestDeserializeForceOn, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    std::vector<SwitchParam> config;
    bool ret = serializer->Deserialize(TEST_JSON_FORCE_ON, config);
    ASSERT_TRUE(ret);
    ASSERT_EQ(config.size(), 1);
    ASSERT_EQ(config[0].key, SwitchKey::BLUETOOTH);
    ASSERT_EQ(config[0].status, SwitchStatus::FORCE_ON);
}

/**
 * @tc.name: TestSerializeSuccess
 * @tc.desc: Test SwitchParamSerializer::Serialize success
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestSerializeSuccess, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    std::vector<SwitchParam> config;
    SwitchParam param{SwitchKey::BLUETOOTH, SwitchStatus::OFF};
    config.push_back(param);
    std::string jsonString;
    bool ret = serializer->Serialize(config, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(jsonString.empty());
}

/**
 * @tc.name: TestSerializeEmptyVector
 * @tc.desc: Test SwitchParamSerializer::Serialize with empty vector
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestSerializeEmptyVector, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    std::vector<SwitchParam> config;
    std::string jsonString;
    bool ret = serializer->Serialize(config, jsonString);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestSerializeMultipleItems
 * @tc.desc: Test SwitchParamSerializer::Serialize with multiple items
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestSerializeMultipleItems, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    std::vector<SwitchParam> config;
    config.push_back({SwitchKey::BLUETOOTH, SwitchStatus::ON});
    config.push_back({SwitchKey::WIFI, SwitchStatus::OFF});
    std::string jsonString;
    bool ret = serializer->Serialize(config, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(jsonString.empty());
}

/**
 * @tc.name: TestGetPolicySuccess
 * @tc.desc: Test SwitchParamSerializer::GetPolicy success
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestGetPolicySuccess, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(SwitchKey::BLUETOOTH));
    data.WriteInt32(static_cast<int32_t>(SwitchStatus::OFF));
    std::vector<SwitchParam> result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_EQ(result.size(), 1);
    ASSERT_EQ(result[0].key, SwitchKey::BLUETOOTH);
    ASSERT_EQ(result[0].status, SwitchStatus::OFF);
}

/**
 * @tc.name: TestGetPolicyInvalidKey
 * @tc.desc: Test SwitchParamSerializer::GetPolicy with invalid key
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestGetPolicyInvalidKey, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    MessageParcel data;
    data.WriteInt32(999);  // invalid key
    data.WriteInt32(static_cast<int32_t>(SwitchStatus::ON));
    std::vector<SwitchParam> result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_EQ(result.size(), 1);
    ASSERT_EQ(result[0].key, SwitchKey::UNKNOWN);
    ASSERT_EQ(result[0].status, SwitchStatus::ON);
}

/**
 * @tc.name: TestGetPolicyInvalidStatus
 * @tc.desc: Test SwitchParamSerializer::GetPolicy with invalid status
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestGetPolicyInvalidStatus, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(SwitchKey::WIFI));
    data.WriteInt32(999);  // invalid status
    std::vector<SwitchParam> result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_EQ(result.size(), 1);
    ASSERT_EQ(result[0].key, SwitchKey::WIFI);
    ASSERT_EQ(result[0].status, SwitchStatus::UNKNOWN);
}

/**
 * @tc.name: TestWritePolicySuccess
 * @tc.desc: Test SwitchParamSerializer::WritePolicy success
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestWritePolicySuccess, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    MessageParcel reply;
    std::vector<SwitchParam> result;
    result.push_back({SwitchKey::BLUETOOTH, SwitchStatus::ON});
    bool ret = serializer->WritePolicy(reply, result);
    ASSERT_TRUE(ret);
    int32_t key = reply.ReadInt32();
    int32_t status = reply.ReadInt32();
    ASSERT_EQ(key, static_cast<int32_t>(SwitchKey::BLUETOOTH));
    ASSERT_EQ(status, static_cast<int32_t>(SwitchStatus::ON));
}

/**
 * @tc.name: TestWritePolicyEmptyVector
 * @tc.desc: Test SwitchParamSerializer::WritePolicy with empty vector
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestWritePolicyEmptyVector, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    MessageParcel reply;
    std::vector<SwitchParam> result;
    bool ret = serializer->WritePolicy(reply, result);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestMergePolicySuccess
 * @tc.desc: Test SwitchParamSerializer::MergePolicy success
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestMergePolicySuccess, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    std::vector<std::vector<SwitchParam>> data;
    std::vector<SwitchParam> admin1;
    admin1.push_back({SwitchKey::BLUETOOTH, SwitchStatus::ON});
    std::vector<SwitchParam> admin2;
    admin2.push_back({SwitchKey::WIFI, SwitchStatus::OFF});
    data.push_back(admin1);
    data.push_back(admin2);
    std::vector<SwitchParam> result;
    bool ret = serializer->MergePolicy(data, result);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestSwitchKeyToString
 * @tc.desc: Test SwitchKeyToString conversion
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestSwitchKeyToString, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    std::vector<SwitchParam> config;
    config.push_back({SwitchKey::NEARLINK, SwitchStatus::ON});
    config.push_back({SwitchKey::BLUETOOTH, SwitchStatus::ON});
    config.push_back({SwitchKey::WIFI, SwitchStatus::ON});
    config.push_back({SwitchKey::NFC, SwitchStatus::ON});
    config.push_back({SwitchKey::UNKNOWN, SwitchStatus::ON});

    std::string jsonString;
    bool ret = serializer->Serialize(config, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(jsonString.find("NEARLINK") != std::string::npos);
    ASSERT_TRUE(jsonString.find("BLUETOOTH") != std::string::npos);
    ASSERT_TRUE(jsonString.find("WIFI") != std::string::npos);
    ASSERT_TRUE(jsonString.find("NFC") != std::string::npos);
    ASSERT_TRUE(jsonString.find("UNKNOWN") != std::string::npos);
}

/**
 * @tc.name: TestSwitchStatusToString
 * @tc.desc: Test SwitchStatusToString conversion
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestSwitchStatusToString, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    std::vector<SwitchParam> config;
    config.push_back({SwitchKey::BLUETOOTH, SwitchStatus::ON});
    config.push_back({SwitchKey::BLUETOOTH, SwitchStatus::OFF});
    config.push_back({SwitchKey::BLUETOOTH, SwitchStatus::FORCE_ON});
    config.push_back({SwitchKey::BLUETOOTH, SwitchStatus::UNKNOWN});

    std::string jsonString;
    bool ret = serializer->Serialize(config, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(jsonString.find("ON") != std::string::npos);
    ASSERT_TRUE(jsonString.find("OFF") != std::string::npos);
    ASSERT_TRUE(jsonString.find("FORCE_ON") != std::string::npos);
    ASSERT_TRUE(jsonString.find("UNKNOWN") != std::string::npos);
}

/**
 * @tc.name: TestStringToSwitchKey
 * @tc.desc: Test StringToSwitchKey conversion
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestStringToSwitchKey, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    std::string jsonString = "[{\"key\":\"NEARLINK\",\"status\":\"ON\"},"
        "{\"key\":\"BLUETOOTH\",\"status\":\"OFF\"},"
        "{\"key\":\"WIFI\",\"status\":\"ON\"},"
        "{\"key\":\"NFC\",\"status\":\"OFF\"}]";
    std::vector<SwitchParam> config;
    bool ret = serializer->Deserialize(jsonString, config);
    ASSERT_TRUE(ret);
    ASSERT_EQ(config.size(), 4);
    ASSERT_EQ(config[0].key, SwitchKey::NEARLINK);
    ASSERT_EQ(config[1].key, SwitchKey::BLUETOOTH);
    ASSERT_EQ(config[2].key, SwitchKey::WIFI);
    ASSERT_EQ(config[3].key, SwitchKey::NFC);
}

/**
 * @tc.name: TestStringToSwitchStatus
 * @tc.desc: Test StringToSwitchStatus conversion
 * @tc.type: FUNC
 */
HWTEST_F(SwitchParamSerializerTest, TestStringToSwitchStatus, TestSize.Level1)
{
    auto serializer = SwitchParamSerializer::GetInstance();
    std::string jsonString = "[{\"key\":\"BLUETOOTH\",\"status\":\"ON\"},"
        "{\"key\":\"BLUETOOTH\",\"status\":\"OFF\"},"
        "{\"key\":\"BLUETOOTH\",\"status\":\"FORCE_ON\"}]";
    std::vector<SwitchParam> config;
    bool ret = serializer->Deserialize(jsonString, config);
    ASSERT_TRUE(ret);
    ASSERT_EQ(config.size(), 3);
    ASSERT_EQ(config[0].status, SwitchStatus::ON);
    ASSERT_EQ(config[1].status, SwitchStatus::OFF);
    ASSERT_EQ(config[2].status, SwitchStatus::FORCE_ON);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
