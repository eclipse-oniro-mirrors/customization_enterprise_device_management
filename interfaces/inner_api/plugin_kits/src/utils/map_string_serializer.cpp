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

#include "map_string_serializer.h"
#include <string_ex.h>

namespace OHOS {
namespace EDM {
bool MapStringSerializer::Deserialize(const std::string &jsonString, std::map<std::string, std::string> &dataObj)
{
    if (jsonString.empty()) {
        return true;
    }
    Json::Value root;
    const auto rawJsonLength = static_cast<int>(jsonString.length());
    JSONCPP_STRING err;
    Json::CharReaderBuilder builder;
    const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    if (!reader->parse(jsonString.c_str(), jsonString.c_str() + rawJsonLength, &root, &err)) {
        EDMLOGE("MapStringSerializer::Deserialize jsonString error: %{public}s", err.c_str());
        return false;
    }
    if (!root.isObject()) {
        EDMLOGE("MapStringSerializer::Deserialize jsonString is not map.");
        return false;
    }
    if (root.empty()) {
        return true;
    }
    for (auto &member : root.getMemberNames()) {
        if (root[member].type() != Json::ValueType::stringValue && root[member].type() != Json::ValueType::intValue &&
            root[member].type() != Json::ValueType::uintValue && root[member].type() != Json::ValueType::booleanValue) {
            EDMLOGE("MapStringSerializer::Deserialize member type is not support.");
            return false;
        }
        dataObj.insert(std::pair<std::string, std::string>(member, root[member].asString()));
    }
    return true;
}

bool MapStringSerializer::Serialize(const std::map<std::string, std::string> &dataObj, std::string &jsonString)
{
    if (dataObj.empty()) {
        jsonString = "";
        return true;
    }
    Json::Value root;
    for (const auto &item : dataObj) {
        root[item.first] = item.second;
    }
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "    ";
    jsonString = Json::writeString(builder, root);
    return true;
}

bool MapStringSerializer::GetPolicy(MessageParcel &data, std::map<std::string, std::string> &result)
{
    std::vector<std::string> keys;
    std::vector<std::string> values;
    if (!data.ReadStringVector(&keys)) {
        EDMLOGE("MapStringSerializer::read map keys fail.");
        return false;
    }
    if (!data.ReadStringVector(&values)) {
        EDMLOGE("MapStringSerializer::read map values fail.");
        return false;
    }
    if (keys.size() != values.size()) {
        return false;
    }
    for (uint64_t i = 0; i < keys.size(); ++i) {
        result.insert(std::make_pair(keys.at(i), values.at(i)));
    }
    return true;
}

bool MapStringSerializer::WritePolicy(MessageParcel &reply, std::map<std::string, std::string> &result)
{
    std::vector<std::string> keys;
    std::vector<std::string> values;
    for (const auto &item : result) {
        keys.push_back(item.first);
        values.push_back(item.second);
    }
    return reply.WriteStringVector(keys) && reply.WriteStringVector(values);
}

bool MapStringSerializer::MergePolicy(std::vector<std::map<std::string, std::string>> &data,
    std::map<std::string, std::string> &result)
{
    if (!data.empty()) {
        result = *(data.rbegin());
    }
    return true;
}
} // namespace EDM
} // namespace OHOS