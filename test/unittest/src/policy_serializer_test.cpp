/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "json_serializer.h"
#include "map_string_serializer.h"
#include "string_serializer.h"

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
    std::u16string value16 = u"s一";
    messageParcel1.WriteString16(value16);
    value = "";
    ASSERT_TRUE(serializer->GetPolicy(messageParcel1, value));
    ASSERT_TRUE(value == "s一");

    MessageParcel messageParcel2;
    value = "s二";
    ASSERT_TRUE(serializer->WritePolicy(messageParcel2, value));
    value16 = u"";
    ASSERT_TRUE(messageParcel2.ReadString16(value16));
    ASSERT_TRUE(value16 == u"s二");

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
    vector<std::u16string> value16 = {
        Str8ToStr16("一"), Str8ToStr16("二"), Str8ToStr16("三"),
        Str8ToStr16("四"), Str8ToStr16("五"), Str8ToStr16("六"),
        Str8ToStr16("七") };
    messageParcel1.WriteString16Vector(value16);
    value = {};
    ASSERT_TRUE(serializer->GetPolicy(messageParcel1, value));
    ASSERT_TRUE(value.size() == 7);

    MessageParcel messageParcel2;
    value = { "v1", "v2", "v3" };
    ASSERT_TRUE(serializer->WritePolicy(messageParcel2, value));
    value16 = {};
    messageParcel2.ReadString16Vector(&value16);
    ASSERT_TRUE(value16.size() == 3);

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
    vector<std::u16string> value16 = {
        uR"({"id":"1","name":"leon","desc":"hello world"})", uR"({"id":"2","name":"job","desc":"two"})",
        uR"({"id":"3","name":"james","desc":"three"})", uR"({"id":"4","name":"bao","desc":"four"})",
        uR"({"id":"5","name":"fox","desc":"five"})"
    };
    messageParcel1.WriteString16Vector(value16);
    ASSERT_TRUE(serializer->GetPolicy(messageParcel1, value));
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
    vector<std::u16string> key16 = {
        Str8ToStr16("一"), Str8ToStr16("二"), Str8ToStr16("三"),
        Str8ToStr16("四"), Str8ToStr16("五"), Str8ToStr16("六"),
        Str8ToStr16("七") };
    messageParcel1.WriteString16Vector(key16);
    vector<std::u16string> value16 = {
        Str8ToStr16("值"), Str8ToStr16("值"), Str8ToStr16("值"),
        Str8ToStr16("值"), Str8ToStr16("值"), Str8ToStr16("值"),
        Str8ToStr16("值") };
    messageParcel1.WriteString16Vector(value16);
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
    vector<std::u16string> key16;
    vector<std::u16string> value16;
    messageParcel2.ReadString16Vector(&key16);
    messageParcel2.ReadString16Vector(&value16);
    ASSERT_TRUE(key16.size() == 4);
    for (std::uint32_t i = 0; i < key16.size(); ++i) {
        ASSERT_EQ(Str16ToStr8(key16.at(i)), "k" + std::to_string(i + 1));
    }
    ASSERT_TRUE(value16.size() == 4);
    for (std::uint32_t i = 0; i < value16.size(); ++i) {
        ASSERT_EQ(Str16ToStr8(value16.at(i)), "v" + std::to_string(i + 1));
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
    std::u16string value16 = Str8ToStr16(R"(["v1","v2"])");
    messageParcel1.WriteString16(value16);
    value = {};
    ASSERT_TRUE(serializer->GetPolicy(messageParcel1, value));
    ASSERT_TRUE(value.isArray() && value.size() == 2);

    MessageParcel messageParcel2;
    value = Json::Value(Json::arrayValue);
    value[0] = 1;
    value[1] = 2;
    value[3] = 3;
    ASSERT_TRUE(serializer->WritePolicy(messageParcel2, value));
    value16 = Str8ToStr16("");
    messageParcel2.ReadString16(value16);
    jsonString = Str16ToStr8(value16);
    sd = remove_if(jsonString.begin(), jsonString.end(), isspace);
    jsonString.erase(sd, jsonString.end());
    ASSERT_EQ(jsonString, R"([1,2,null,3])");
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
