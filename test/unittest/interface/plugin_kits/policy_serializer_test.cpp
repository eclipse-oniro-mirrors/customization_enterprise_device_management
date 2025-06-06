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
#include "array_string_serializer.h"
#include "bool_serializer.h"
#include "cjson_serializer.h"
#include "func_code_utils.h"
#include "long_serializer.h"
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
    ASSERT_TRUE(serializer->Deserialize("", boolValue));
    ASSERT_TRUE(serializer->Deserialize("true", boolValue));
    ASSERT_EQ(boolValue, true);
    ASSERT_FALSE(serializer->Deserialize("truee", boolValue));

    boolValue = true;
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
    serializer->MergePolicy(policyValues, boolValue);
    ASSERT_EQ(boolValue, true);

    boolValue = true;
    policyValues = { false, false, false, false, false };
    serializer->MergePolicy(policyValues, boolValue);
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
    serializer->MergePolicy(policyValues, value);
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
    serializer->MergePolicy(policyValues, value);
    ASSERT_TRUE(value.size() == 9);
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
    serializer->MergePolicy(policyValues, value);
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
    
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "string", "str");
    cJSON_AddStringToObject(root, "bool", "true");
    cJSON_AddStringToObject(root, "int", "1");
    
    char* jsonString = cJSON_PrintUnformatted(root);
    std::string jsonStr(jsonString);
    cJSON_free(jsonString);
    
    std::map<std::string, std::string> result;
    ASSERT_TRUE(serializer->Deserialize(jsonStr, result));
    ASSERT_TRUE(result["string"] == "str");
    ASSERT_TRUE(result["bool"] == "true");
    ASSERT_TRUE(result["int"] == "1");
    
    cJSON_Delete(root);
}

/**
 * @tc.name: MAP_STRING_Serializer_DeserializeFail
 * @tc.desc: Test MapStringSerializer.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, MAP_STRING_Serializer_DeserializeFail, TestSize.Level1)
{
    auto serializer = MapStringSerializer::GetInstance();
    
    cJSON* root = cJSON_CreateObject();
    cJSON* sub = cJSON_CreateObject();
    cJSON_AddStringToObject(sub, "key", "value");
    cJSON_AddItemToObject(root, "object", sub);
    
    char* jsonString = cJSON_Print(root);
    std::string jsonStr(jsonString);
    cJSON_free(jsonString);
    
    std::map<std::string, std::string> result;
    ASSERT_FALSE(serializer->Deserialize(jsonStr, result));
    ASSERT_TRUE(result.empty());
    
    cJSON_Delete(root);
}

/**
 * @tc.name: JSON
 * @tc.desc: Test JsonSerializer.
 * @tc.type: FUNC
 */
HWTEST_F(PolicySerializerTest, JSON, TestSize.Level1)
{
    auto serializer = CjsonSerializer::GetInstance();
    
    cJSON* value = cJSON_CreateObject();
    cJSON_AddStringToObject(value, "k1", "v1");
    cJSON_AddStringToObject(value, "k2", "v2");
    cJSON_AddNumberToObject(value, "k3", 3);
    
    std::string jsonString;
    ASSERT_TRUE(serializer->Serialize(value, jsonString));
    auto sd = std::remove_if(jsonString.begin(), jsonString.end(), isspace);
    jsonString.erase(sd, jsonString.end());
    ASSERT_EQ(jsonString, R"({"k1":"v1","k2":"v2","k3":3})");
    cJSON_Delete(value);

    jsonString = R"(["v1","v2","v3","v4","v5","v6"])";
    value = nullptr;
    ASSERT_TRUE(serializer->Deserialize(jsonString, value));
    ASSERT_TRUE(cJSON_IsArray(value) && cJSON_GetArraySize(value) == 6);
    cJSON_Delete(value);

    MessageParcel messageParcel1;
    std::string value2 = R"(["v1","v2"])";
    messageParcel1.WriteString(value2);
    value = nullptr;
    ASSERT_TRUE(serializer->GetPolicy(messageParcel1, value));
    ASSERT_TRUE(cJSON_IsArray(value) && cJSON_GetArraySize(value) == 2);
    cJSON_Delete(value);

    MessageParcel messageParcel2;
    value = cJSON_CreateArray();
    cJSON_AddItemToArray(value, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(value, cJSON_CreateNumber(2));
    cJSON_AddItemToArray(value, cJSON_CreateNull());
    cJSON_AddItemToArray(value, cJSON_CreateNumber(3));
    ASSERT_TRUE(serializer->WritePolicy(messageParcel2, value));
    value2 = "";
    messageParcel2.ReadString(value2);
    jsonString = value2;
    sd = std::remove_if(jsonString.begin(), jsonString.end(), isspace);
    jsonString.erase(sd, jsonString.end());
    ASSERT_EQ(jsonString, R"([1,2,null,3])");
    cJSON_Delete(value);

    std::vector<cJSON*> vec;
    value = cJSON_Parse(jsonString.c_str());
    ASSERT_TRUE(value != nullptr);
    vec.push_back(value);
    serializer->MergePolicy(vec, value);
    ASSERT_TRUE(vec.size() == 1);
    cJSON_Delete(value);
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
