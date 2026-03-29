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

#include "bluetooth_protocol_policy_serializer.h"
#include "bluetooth_protocol_models.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class BluetoothProtocolPolicySerializerTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void BluetoothProtocolPolicySerializerTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void BluetoothProtocolPolicySerializerTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDeserializeEmpty
 * @tc.desc: Test BluetoothProtocolPolicySerializer::Deserialize when jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestDeserializeEmpty, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::string jsonString;
    BluetoothProtocolPolicy policy;
    bool ret = serializer->Deserialize(jsonString, policy);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(policy.protocolDenyList.empty());
    ASSERT_TRUE(policy.protocolRecDenyList.empty());
}

/**
 * @tc.name: TestDeserializeInvalidJson
 * @tc.desc: Test BluetoothProtocolPolicySerializer::Deserialize when jsonString is invalid
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestDeserializeInvalidJson, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::string jsonString = "{invalid json";
    BluetoothProtocolPolicy policy;
    bool ret = serializer->Deserialize(jsonString, policy);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestDeserializeLegacyFormat
 * @tc.desc: Test BluetoothProtocolPolicySerializer::Deserialize with legacy array format
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestDeserializeLegacyFormat, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::string jsonString = "[0, 1, 2]";
    BluetoothProtocolPolicy policy;
    bool ret = serializer->Deserialize(jsonString, policy);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(policy.protocolDenyList.empty());
}

/**
 * @tc.name: TestDeserializeNewFormat
 * @tc.desc: Test BluetoothProtocolPolicySerializer::Deserialize with new object format
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestDeserializeNewFormat, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::string jsonString = R"({
        "ProtocolDenyList": {
            "100": ["GATT", "SPP"],
            "101": ["OPP"]
        },
        "ProtocolRecDenyList": {
            "100": ["GATT"],
            "101": ["SPP", "OPP"]
        }
    })";
    BluetoothProtocolPolicy policy;
    bool ret = serializer->Deserialize(jsonString, policy);
    ASSERT_TRUE(ret);
    ASSERT_EQ(policy.protocolDenyList.size(), 2);
    ASSERT_EQ(policy.protocolRecDenyList.size(), 2);
    ASSERT_EQ(policy.protocolDenyList[100].size(), 2);
    ASSERT_EQ(policy.protocolRecDenyList[100].size(), 1);
}

/**
 * @tc.name: TestDeserializePartialFormat
 * @tc.desc: Test BluetoothProtocolPolicySerializer::Deserialize with partial fields
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestDeserializePartialFormat, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::string jsonString = R"({
        "ProtocolDenyList": {
            "100": ["GATT", "SPP"]
        }
    })";
    BluetoothProtocolPolicy policy;
    bool ret = serializer->Deserialize(jsonString, policy);
    ASSERT_TRUE(ret);
    ASSERT_EQ(policy.protocolDenyList.size(), 1);
    ASSERT_TRUE(policy.protocolRecDenyList.empty());
}

/**
 * @tc.name: TestSerializeEmpty
 * @tc.desc: Test BluetoothProtocolPolicySerializer::Serialize with empty policy
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestSerializeEmpty, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    BluetoothProtocolPolicy policy;
    std::string jsonString;
    bool ret = serializer->Serialize(policy, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(jsonString.empty());
}

/**
 * @tc.name: TestSerializeWithData
 * @tc.desc: Test BluetoothProtocolPolicySerializer::Serialize with data
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestSerializeWithData, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    BluetoothProtocolPolicy policy;
    policy.protocolDenyList[100] = {"GATT", "SPP"};
    policy.protocolDenyList[101] = {"OPP"};
    policy.protocolRecDenyList[100] = {"GATT"};
    policy.protocolRecDenyList[101] = {"SPP", "OPP"};

    std::string jsonString;
    bool ret = serializer->Serialize(policy, jsonString);
    ASSERT_TRUE(ret);
    ASSERT_FALSE(jsonString.empty());
    ASSERT_NE(jsonString.find("ProtocolDenyList"), std::string::npos);
    ASSERT_NE(jsonString.find("ProtocolRecDenyList"), std::string::npos);
    ASSERT_NE(jsonString.find("GATT"), std::string::npos);
    ASSERT_NE(jsonString.find("SPP"), std::string::npos);
    ASSERT_NE(jsonString.find("OPP"), std::string::npos);
}

/**
 * @tc.name: TestSerializeDeserializeRoundTrip
 * @tc.desc: Test serialization and deserialization round trip
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestSerializeDeserializeDeserializeRoundTrip, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    BluetoothProtocolPolicy originalPolicy;
    originalPolicy.protocolDenyList[100] = {"GATT", "SPP"};
    originalPolicy.protocolRecDenyList[100] = {"OPP"};

    std::string jsonString;
    ASSERT_TRUE(serializer->Serialize(originalPolicy, jsonString));

    BluetoothProtocolPolicy deserializedPolicy;
    ASSERT_TRUE(serializer->Deserialize(jsonString, deserializedPolicy));

    ASSERT_EQ(deserializedPolicy.protocolDenyList.size(), originalPolicy.protocolDenyList.size());
    ASSERT_EQ(deserializedPolicy.protocolRecDenyList.size(), originalPolicy.protocolRecDenyList.size());
}

/**
 * @tc.name: TestGetPolicySetDisallowedProtocols
 * @tc.desc: Test BluetoothProtocolPolicySerializer::GetPolicy with SET_DISALLOWED_PROTOCOLS
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestGetPolicySetDisallowedProtocols, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    MessageParcel data;
    data.WriteInt32(BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS);
    data.WriteInt32(100);
    std::vector<int32_t> protocols = {0, 1, 2};
    data.WriteInt32Vector(protocols);

    BluetoothProtocolPolicy result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_EQ(result.protocolDenyList.size(), 1);
    ASSERT_EQ(result.protocolDenyList[100].size(), 3);
}

/**
 * @tc.name: TestGetPolicySetDisallowedWithPolicySendOnly
 * @tc.desc: Test BluetoothProtocolPolicySerializer::GetPolicy with SEND_ONLY policy
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestGetPolicySetDisallowedWithPolicySendOnlyOnly, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    MessageParcel data;
    data.WriteInt32(BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS_WITH_POLICY);
    data.WriteInt32(100);
    std::vector<int32_t> protocols = {0, 1};
    data.WriteInt32Vector(protocols);
    data.WriteInt32(static_cast<int32_t>(TransferPolicy::SEND_ONLY));

    BluetoothProtocolPolicy result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_EQ(result.protocolDenyList.size(), 1);
    ASSERT_EQ(result.protocolDenyList[100].size(), 2);
    ASSERT_TRUE(result.protocolRecDenyList.empty());
}

/**
 * @tc.name: TestGetPolicySetDisallowedWithPolicyReceiveOnly
 * @tc.desc: Test BluetoothProtocolPolicySerializer::GetPolicy with RECEIVE_ONLY policy
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestGetPolicySetDisallowedWithPolicyReceiveOnlyOnly, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    MessageParcel data;
    data.WriteInt32(BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS_WITH_POLICY);
    data.WriteInt32(100);
    std::vector<int32_t> protocols = {0, 1};
    data.WriteInt32Vector(protocols);
    data.WriteInt32(static_cast<int32_t>(TransferPolicy::RECEIVE_ONLY));

    BluetoothProtocolPolicy result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(result.protocolDenyList.empty());
    ASSERT_EQ(result.protocolRecDenyList.size(), 1);
    ASSERT_EQ(result.protocolRecDenyList[100].size(), 2);
}

/**
 * @tc.name: TestGetPolicySetDisallowedWithPolicyReceiveSend
 * @tc.desc: Test BluetoothProtocolPolicySerializer::GetPolicy with RECEIVE_SEND policy
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestGetPolicySetDisallowedWithPolicyReceiveSend, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    MessageParcel data;
    data.WriteInt32(BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS_WITH_POLICY);
    data.WriteInt32(100);
    std::vector<int32_t> protocols = {0, 1, 2};
    data.WriteInt32Vector(protocols);
    data.WriteInt32(static_cast<int32_t>(TransferPolicy::RECEIVE_SEND));

    BluetoothProtocolPolicy result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_EQ(result.protocolDenyList.size(), 1);
    ASSERT_EQ(result.protocolRecDenyList.size(), 1);
    ASSERT_EQ(result.protocolDenyList[100].size(), 3);
    ASSERT_EQ(result.protocolRecDenyList[100].size(), 3);
}

/**
 * @tc.name: TestGetPolicyInvalidProtocolValue
 * @tc.desc: Test BluetoothProtocolPolicySerializer::GetPolicy with invalid protocol value
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestGetPolicyInvalidProtocolValue, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    MessageParcel data;
    data.WriteInt32(BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS);
    data.WriteInt32(100);
    std::vector<int32_t> protocols = {0, 1, 99}; // 99 is invalid
    data.WriteInt32Vector(protocols);

    BluetoothProtocolPolicy result;
    bool ret = serializer->GetPolicy(data, result);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test BluetoothProtocolPolicySerializer::WritePolicy
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestWritePolicy, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    MessageParcel reply;
    BluetoothProtocolPolicy policy;
    policy.protocolDenyList[100] = {"GATT", "SPP"};

    bool ret = serializer->WritePolicy(reply, policy);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestMergePolicyEmpty
 * @tc.desc: Test BluetoothProtocolPolicySerializer::MergePolicy with empty data
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestMergePolicyEmpty, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::vector<BluetoothProtocolPolicy> data;
    BluetoothProtocolPolicy result;

    bool ret = serializer->MergePolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(result.protocolDenyList.empty());
    ASSERT_TRUE(result.protocolRecDenyList.empty());
}

/**
 * @tc.name: TestMergePolicySingle
 * @tc.desc: Test BluetoothProtocolPolicySerializer::MergePolicy with single policy
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestMergePolicySingle, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::vector<BluetoothProtocolPolicy> data;
    BluetoothProtocolPolicy policy1;
    policy1.protocolDenyList[100] = {"GATT", "SPP"};
    policy1.protocolRecDenyList[100] = {"OPP"};
    data.push_back(policy1);

    BluetoothProtocolPolicy result;
    bool ret = serializer->MergePolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_EQ(result.protocolDenyList.size(), 1);
    ASSERT_EQ(result.protocolRecDenyList.size(), 1);
    ASSERT_EQ(result.protocolDenyList[100].size(), 2);
    ASSERT_EQ(result.protocolRecDenyList[100].size(), 1);
}

/**
 * @tc.name: TestMergePolicyMultiple
 * @tc.desc: Test BluetoothProtocolPolicySerializer::MergePolicy with multiple policies
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestMergePolicyMultiple, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::vector<BluetoothProtocolPolicy> data;

    BluetoothProtocolPolicy policy1;
    policy1.protocolDenyList[100] = {"GATT", "SPP"};
    data.push_back(policy1);

    BluetoothProtocolPolicy policy2;
    policy2.protocolDenyList[100] = {"OPP"};
    policy2.protocolRecDenyList[100] = {"GATT"};
    data.push_back(policy2);

    BluetoothProtocolPolicy policy3;
    policy3.protocolDenyList[101] = {"SPP"};
    data.push_back(policy3);

    BluetoothProtocolPolicy result;
    bool ret = serializer->MergePolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_EQ(result.protocolDenyList.size(), 2);
    ASSERT_EQ(result.protocolRecDenyList.size(), 1);
    ASSERT_EQ(result.protocolDenyList[100].size(), 3); // GATT, SPP, OPP (deduplicated)
    ASSERT_EQ(result.protocolDenyList[101].size(), 1);
    ASSERT_EQ(result.protocolRecDenyList[100].size(), 1);
}

/**
 * @tc.name: TestMergePolicyDeduplication
 * @tc.desc: Test BluetoothProtocolPolicySerializer::MergePolicy deduplicates protocols
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestMergePolicyDeduplication, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::vector<BluetoothProtocolPolicy> data;

    BluetoothProtocolPolicy policy1;
    policy1.protocolDenyList[100] = {"GATT", "SPP", "OPP"};
    data.push_back(policy1);

    BluetoothProtocolPolicy policy2;
    policy2.protocolDenyList[100] = {"GATT", "SPP", "OPP"}; // Duplicate
    data.push_back(policy2);

    BluetoothProtocolPolicy result;
    bool ret = serializer->MergePolicy(data, result);
    ASSERT_TRUE(ret);
    ASSERT_EQ(result.protocolDenyList[100].size(), 3); // Should be deduplicated
}

/**
 * @tc.name: TestIntToProtocolStrValid
 * @tc.desc: Test BluetoothProtocolPolicySerializer::IntToProtocolStr with valid values
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestIntToProtocolStrValid, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::string str;

    ASSERT_TRUE(serializer->IntToProtocolStr(0, str));
    ASSERT_EQ(str, "GATT");

    ASSERT_TRUE(serializer->IntToProtocolStr(1, str));
    ASSERT_EQ(str, "SPP");

    ASSERT_TRUE(serializer->IntToProtocolStr(2, str));
    ASSERT_EQ(str, "OPP");
}

/**
 * @tc.name: TestIntToProtocolStrInvalid
 * @tc.desc: Test BluetoothProtocolPolicySerializer::IntToProtocolStr with invalid values
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestIntToProtocolStrInvalid, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::string str;

    ASSERT_FALSE(serializer->IntToProtocolStr(-1, str));
    ASSERT_FALSE(serializer->IntToProtocolStr(3, str));
    ASSERT_FALSE(serializer->IntToProtocolStr(99, str));
}

/**
 * @tc.name: TestStrToProtocolIntValid
 * @tc.desc: Test BluetoothProtocolPolicySerializer::StrToProtocolInt with valid strings
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestStrToProtocolIntValid, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    int32_t value;

    ASSERT_TRUE(serializer->StrToProtocolInt("GATT", value));
    ASSERT_EQ(value, 0);

    ASSERT_TRUE(serializer->StrToProtocolInt("SPP", value));
    ASSERT_EQ(value, 1);

    ASSERT_TRUE(serializer->StrToProtocolInt("OPP", value));
    ASSERT_EQ(value, 2);
}

/**
 * @tc.name: TestStrToProtocolIntInvalid
 * @tc.desc: Test BluetoothProtocolPolicySerializer::StrToProtocolInt with invalid strings
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothProtocolPolicySerializerTest, TestStrToProtocolIntInvalid, TestSize.Level1)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    int32_t value;

    ASSERT_FALSE(serializer->StrToProtocolInt("INVALID", value));
    ASSERT_FALSE(serializer->StrToProtocolInt("", value));
    ASSERT_FALSE(serializer->StrToProtocolInt("gatt", value)); // Case sensitive
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
