/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "array_map_serializer.h"
#include "array_string_serializer.h"
#include "bool_serializer.h"
#include "func_code_utils.h"
#include "long_serializer.h"
#include "map_string_serializer.h"
#include "string_serializer.h"
#include "utils/json_serializer.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {
class PolicySerializerTest : public testing::Test {};

/**
 * @tc.name: BOOL
 * @tc.desc: Test BoolSerializer.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, BOOL, TestSize.Level1)
{
    auto serializer = BoolSerializer::GetInstance();
    string boolJsonString;
    ASSERT_TRUE(serializer->Serialize(true, boolJsonString));
    ASSERT_EQ(boolJsonString, "true");
    ASSERT_NE(boolJsonString, "false");

    bool boolValue = false;
    ASSERT_FALSE(serializer->Deserialize("", boolValue));
    ASSERT_TRUE(serializer->Deserialize("true", boolValue));
    ASSERT_EQ(boolValue, true);
    ASSERT_FALSE(serializer->Deserialize("truee", boolValue));

    MessageParcel messageParcel1;
    messageParcel1.WriteBool(false);
    ASSERT_TRUE(serializer->GetPolicy(messageParcel1, boolValue));
    ASSERT_EQ(boolValue, false);

    MessageParcel messageParcel2;
    boolValue = true;
    ASSERT_TRUE(serializer->WritePolicy(messageParcel2, boolValue));
    ASSERT_EQ(messageParcel2.ReadBool(), true);


    boolValue = false;
    vector<bool> policyValues { false, true, false, false, true };
    ASSERT_TRUE(serializer->MergePolicy(policyValues, boolValue));
    ASSERT_EQ(boolValue, true);

    boolValue = true;
    policyValues = { false, false, false, false, false };
    ASSERT_TRUE(serializer->MergePolicy(policyValues, boolValue));
    ASSERT_EQ(boolValue, false);
}

/**
 * @tc.name: STRING
 * @tc.desc: Test StringSerializer.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, STRING, TestSize.Level1)
{
    auto serializer = StringSerializer::GetInstance();
    string value = "s1";
    string jsonString;
    ASSERT_TRUE(serializer->Serialize(value, jsonString));
    ASSERT_EQ(jsonString, "s1");

    jsonString = "s2";
    ASSERT_TRUE(serializer->Deserialize(jsonString, value));
    ASSERT_TRUE(value.length() == 2);

    MessageParcel messageParcel1;
    std::string value2 = "s一";
    messageParcel1.WriteString(value2);
    value = "";
    ASSERT_TRUE(serializer->GetPolicy(messageParcel1, value));
    ASSERT_TRUE(value == "s一");

    MessageParcel messageParcel2;
    value = "s二";
    ASSERT_TRUE(serializer->WritePolicy(messageParcel2, value));
    value2 = "";
    ASSERT_TRUE(messageParcel2.ReadString(value2));
    ASSERT_TRUE(value2 == "s二");

    vector<string> policyValues { "v1", "v2", "v3" };
    ASSERT_TRUE(serializer->MergePolicy(policyValues, value));
    ASSERT_TRUE(value == "v3");
}

/**
 * @tc.name: ARRAY_STRING
 * @tc.desc: Test ArrayStringSerializer.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, ARRAY_STRING, TestSize.Level1)
{
    auto serializer = ArrayStringSerializer::GetInstance();
    vector<string> value = { "v1", "v2", "v3", "v4", "v5" };
    string jsonString;
    ASSERT_TRUE(serializer->Serialize(value, jsonString));
    auto sd = remove_if(jsonString.begin(), jsonString.end(), isspace);
    jsonString.erase(sd, jsonString.end());
    ASSERT_EQ(jsonString, R"(["v1","v2","v3","v4","v5"])");

    jsonString = R"(["v1","v2","v3","v4","v5","v6"])";
    ASSERT_TRUE(serializer->Deserialize(jsonString, value));
    ASSERT_TRUE(value.size() == 6);
    ASSERT_FALSE(serializer->Deserialize(R"(["v1","v2","v3","v4","v5""v6"])", value));

    MessageParcel messageParcel1;
    vector<std::string> value2 = { "一", "二", "三", "四", "五", "六", "七" };
    messageParcel1.WriteStringVector(value2);
    value = {};
    ASSERT_TRUE(serializer->GetPolicy(messageParcel1, value));
    ASSERT_TRUE(value.size() == 7);
    serializer->Deduplication(value);
    ASSERT_TRUE(value.size() == 7);
    ArraySerializer<std::string, std::vector<std::string>> testArraySerializer;
    testArraySerializer.Deduplication(value);
    ASSERT_TRUE(value.size() == 7);
    MessageParcel messageParcel2;
    value = { "v1", "v2", "v3" };
    ASSERT_TRUE(serializer->WritePolicy(messageParcel2, value));
    value2 = {};
    messageParcel2.ReadStringVector(&value2);
    ASSERT_TRUE(value2.size() == 3);

    vector<vector<string>> policyValues {{ "v1",   "v2",   "v3" },
                                         { "vv1",  "vv2",  "vv3" },
                                         { "vvv1", "vvv2", "vvv3" },
                                         { "v1",   "v2",   "v3" },
                                         { "vv1",  "vv2",  "vv3" }};
    ASSERT_TRUE(serializer->MergePolicy(policyValues, value));
    ASSERT_TRUE(value.size() == 9);
}

/**
 * @tc.name: ArrayMapStringSerializer
 * @tc.desc: Test ArrayMapSerializer::Serialize.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, ArrayMapStringSerializer, TestSize.Level1)
{
    auto serializer = ArrayMapSerializer::GetInstance();
    vector<map<string, string>> value = {
        {
            { "id", "1" },
            { "name", "leon" },
            { "desc", "hello" },
        },
        {
            { "id", "2" },
            { "name", "job" },
            { "desc", "world" },
        }
    };
    string exceptStr;
    string jsonString;
    ASSERT_TRUE(serializer->Serialize(value, jsonString));
    auto sd = remove_if(jsonString.begin(), jsonString.end(), isspace);
    jsonString.erase(sd, jsonString.end());
    exceptStr = R"(["{\n\"desc\":\"hello\",\n\"id\":\"1\",\n\"name\":\"leon\"\n}")";
    exceptStr.append(R"(,"{\n\"desc\":\"world\",\n\"id\":\"2\",\n\"name\":\"job\"\n}"])");
    ASSERT_EQ(jsonString, exceptStr);
}

/**
 * @tc.name: ArrayMapStringDeserialize
 * @tc.desc: Test ArrayMapSerializer::Deserialize.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, ArrayMapStringDeserialize, TestSize.Level1)
{
    auto serializer = ArrayMapSerializer::GetInstance();
    vector<map<string, string>> value;
    std::string jsonString = R"([{"desc":"hello","id":"1","name":"leon"},{"desc":"world","id":"2","name":"job"}])";
    ASSERT_TRUE(serializer->Deserialize(jsonString, value));
    ASSERT_TRUE(value.size() == 2);

    map<string, string> expectZero = {
        { "id",   "1" },
        { "name", "leon" },
        { "desc", "hello" },
    };
    ASSERT_TRUE(value.at(0) == expectZero);
    map<string, string> expectOne = {
        { "id",   "2" },
        { "name", "job" },
        { "desc", "world" },
    };
    ASSERT_TRUE(value.at(1) == expectOne);
}

/**
 * @tc.name: ArrayMapStringGetPolicy
 * @tc.desc: Test ArrayMapSerializer::GetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, ArrayMapStringGetPolicy, TestSize.Level1)
{
    auto serializer = ArrayMapSerializer::GetInstance();
    vector<map<string, string>> value;
    MessageParcel messageParcel1;
    vector<std::string> value2 = {
        R"({"id":"1","name":"leon","desc":"hello world"})",
        R"({"id":"2","name":"job","desc":"two"})",
        R"({"id":"3","name":"james","desc":"three"})",
        R"({"id":"4","name":"bao","desc":"four"})",
        R"({"id":"5","name":"fox","desc":"five"})"
    };
    messageParcel1.WriteStringVector(value2);
    ASSERT_TRUE(serializer->GetPolicy(messageParcel1, value));
    ASSERT_TRUE(value.size() == 5);
    serializer->Deduplication(value);
    ASSERT_TRUE(value.size() == 5);
}

/**
 * @tc.name: ArrayMapStringWritePolicy
 * @tc.desc: Test ArrayMapSerializer::WritePolicy.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, ArrayMapStringWritePolicy, TestSize.Level1)
{
    MessageParcel messageParcel2;
    auto serializer = ArrayMapSerializer::GetInstance();
    vector<map<string, string>> value = {
        {
            { "id", "1" },
            { "name", "leon" },
            { "desc", "hello" },
        },
        {
            { "id", "2" },
            { "name", "job" },
            { "desc", "world" },
        }
    };
    ASSERT_TRUE(serializer->WritePolicy(messageParcel2, value));

    value = {};
    ASSERT_TRUE(serializer->GetPolicy(messageParcel2, value));
    ASSERT_TRUE(value.size() == 2);
    serializer->Deduplication(value);
    ASSERT_TRUE(value.size() == 2);
}

/**
 * @tc.name: ArrayMapStringMergePolicy
 * @tc.desc: Test ArrayMapSerializer::MergePolicy.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, ArrayMapStringMergePolicy, TestSize.Level1)
{
    auto serializer = ArrayMapSerializer::GetInstance();
    vector<map<string, string>> value;
    vector<vector<map<string, string>>> policyValues {
        {
            {
                { "id", "1" },
                { "name", "leon" },
                { "desc", "hello" },
            },
            {
                { "id", "2" },
                { "name", "job" },
                { "desc", "world" },
            }
        },
        {
            {
                { "id", "1" },
                { "name", "leon" },
                { "desc", "hello" },
            },
            {
                { "id", "3" },
                { "name", "james" },
            }
        }
    };
    ASSERT_TRUE(serializer->MergePolicy(policyValues, value));
    ASSERT_TRUE(value.size() == 3);
}

/**
 * @tc.name: MAP_STRING
 * @tc.desc: Test MapStringSerializer.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, MAP_STRING, TestSize.Level1)
{
    auto serializer = MapStringSerializer::GetInstance();
    map<string, string> value = {
        { "k1", "v1" },
        { "k2", "v2" },
        { "k3", "v3" },
        { "k4", "v4" },
    };
    string jsonString;
    ASSERT_TRUE(serializer->Serialize(value, jsonString));
    auto sd = remove_if(jsonString.begin(), jsonString.end(), isspace);
    jsonString.erase(sd, jsonString.end());
    ASSERT_EQ(jsonString, R"({"k1":"v1","k2":"v2","k3":"v3","k4":"v4"})");

    jsonString = R"({"k1":"v1","k2":"v2","k3":"v3","k4":"v4"})";
    ASSERT_TRUE(serializer->Deserialize(jsonString, value));
    ASSERT_TRUE(value.size() == 4);
    ASSERT_FALSE(serializer->Deserialize(R"(["v1","v2","v3","v4","v5","v6"])", value));

    MessageParcel messageParcel1;
    vector<std::string> key2 = {
        "一", "二", "三",
        "四", "五", "六",
        "七" };
    messageParcel1.WriteStringVector(key2);
    vector<std::string> value2 = {
        "值", "值", "值",
        "值", "值", "值",
        "值" };
    messageParcel1.WriteStringVector(value2);
    value = {};
    ASSERT_TRUE(serializer->GetPolicy(messageParcel1, value));
    ASSERT_TRUE(value.size() == 7);
    for (auto const &entry:value) {
        ASSERT_EQ(entry.second, "值");
    }
}

/**
 * @tc.name: MAP_STRING_002
 * @tc.desc: Test MapStringSerializer.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, MAP_STRING_002, TestSize.Level1)
{
    auto serializer = MapStringSerializer::GetInstance();
    map<string, string> value = {
        { "k1", "v1" },
        { "k2", "v2" },
        { "k3", "v3" },
        { "k4", "v4" },
    };
    MessageParcel messageParcel2;
    value = {
        { "k1", "v1" },
        { "k2", "v2" },
        { "k3", "v3" },
        { "k4", "v4" },
    };
    ASSERT_TRUE(serializer->WritePolicy(messageParcel2, value));
    vector<std::string> key4;
    vector<std::string> value4;
    messageParcel2.ReadStringVector(&key4);
    messageParcel2.ReadStringVector(&value4);
    ASSERT_TRUE(key4.size() == 4);
    for (std::uint32_t i = 0; i < key4.size(); ++i) {
        ASSERT_EQ(key4.at(i), "k" + std::to_string(i + 1));
    }
    ASSERT_TRUE(value4.size() == 4);
    for (std::uint32_t i = 0; i < value4.size(); ++i) {
        ASSERT_EQ(value4.at(i), "v" + std::to_string(i + 1));
    }

    map<string, string> value1 = {
        { "k1", "v1" },
    };
    map<string, string> value2 = {
        { "k1", "v1" },
        { "k2", "v2" },
        { "k3", "v3" },
    };
    map<string, string> value3 = {
        { "k3", "v3" },
        { "k4", "v4" },
    };
    value = {};
    vector<map<string, string>> policyValues { value1, value2, value3 };
    ASSERT_TRUE(serializer->MergePolicy(policyValues, value));
    ASSERT_TRUE(value3 == value);
}

/**
 * @tc.name: MAP_STRING_Serializer_Deserialize
 * @tc.desc: Test MapStringSerializer.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, MAP_STRING_Serializer_Deserialize, TestSize.Level1)
{
    auto serializer = MapStringSerializer::GetInstance();
    Json::Value root;
    root["string"] = "str";
    root["bool"] = true;
    root["int"] = 1;
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "    ";
    std::string jsonString = Json::writeString(builder, root);
    std::map<std::string, std::string> result;
    ASSERT_TRUE(serializer->Deserialize(jsonString, result));
    ASSERT_TRUE(result["string"] == "str");
    ASSERT_TRUE(result["bool"] == "true");
    ASSERT_TRUE(result["int"] == "1");
}

/**
 * @tc.name: MAP_STRING_Serializer_DeserializeFail
 * @tc.desc: Test MapStringSerializer.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, MAP_STRING_Serializer_DeserializeFail, TestSize.Level1)
{
    auto serializer = MapStringSerializer::GetInstance();
    Json::Value root;
    Json::Value sub;
    sub["key"] = "value";
    root["object"] = sub;
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "    ";
    std::string jsonString = Json::writeString(builder, root);
    std::map<std::string, std::string> result;
    ASSERT_FALSE(serializer->Deserialize(jsonString, result));
    ASSERT_TRUE(result.empty());
}

/**
 * @tc.name: JSON
 * @tc.desc: Test JsonSerializer.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, JSON, TestSize.Level1)
{
    auto serializer = JsonSerializer::GetInstance();
    Json::Value value;
    value["k1"] = "v1";
    value["k2"] = "v2";
    value["k3"] = 3;
    string jsonString;
    ASSERT_TRUE(serializer->Serialize(value, jsonString));
    auto sd = remove_if(jsonString.begin(), jsonString.end(), isspace);
    jsonString.erase(sd, jsonString.end());
    ASSERT_EQ(jsonString, R"({"k1":"v1","k2":"v2","k3":3})");

    jsonString = R"(["v1","v2","v3","v4","v5","v6"])";
    ASSERT_TRUE(serializer->Deserialize(jsonString, value));
    ASSERT_TRUE(value.isArray() && value.size() == 6);

    MessageParcel messageParcel1;
    std::string value2 = R"(["v1","v2"])";
    messageParcel1.WriteString(value2);
    value = {};
    ASSERT_TRUE(serializer->GetPolicy(messageParcel1, value));
    ASSERT_TRUE(value.isArray() && value.size() == 2);

    MessageParcel messageParcel2;
    value = Json::Value(Json::arrayValue);
    value[0] = 1;
    value[1] = 2;
    value[3] = 3;
    ASSERT_TRUE(serializer->WritePolicy(messageParcel2, value));
    value2 = "";
    messageParcel2.ReadString(value2);
    jsonString = value2;
    sd = remove_if(jsonString.begin(), jsonString.end(), isspace);
    jsonString.erase(sd, jsonString.end());
    ASSERT_EQ(jsonString, R"([1,2,null,3])");

    std::vector<Json::Value> vec = {jsonString};
    ASSERT_TRUE(serializer->MergePolicy(vec, value));
    ASSERT_TRUE(vec.size() == 1);
}

/**
 * @tc.name: Long
 * @tc.desc: Test LongSerializer.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, Long, TestSize.Level1)
{
    auto serializer = LongSerializer::GetInstance();
    std::string testString = "123456";
    std::string jsonString = testString;
    int64_t res = 0;
    ASSERT_TRUE(serializer->Deserialize(jsonString, res));
    ASSERT_EQ(res, 123456);

    jsonString = "";
    ASSERT_TRUE(serializer->Serialize(res, jsonString));
    ASSERT_EQ(jsonString, testString);

    MessageParcel data;
    data.WriteInt64(1);
    ASSERT_TRUE(serializer->GetPolicy(data, res));
    ASSERT_TRUE(res == 1);

    MessageParcel reply;
    res = 1;
    ASSERT_TRUE(serializer->WritePolicy(reply, res));
    int64_t temp = 0;
    reply.ReadInt64(temp);
    ASSERT_TRUE(temp == 1);

    std::vector<int64_t> vec = {1, 2, 3, 4, 5};
    serializer->MergePolicy(vec, res);
    ASSERT_TRUE(res == 5);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
