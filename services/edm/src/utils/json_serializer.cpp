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

#include "json_serializer.h"
#include <string_ex.h>

namespace OHOS {
namespace EDM {
bool JsonSerializer::Deserialize(const std::string &jsonString, Json::Value &dataObj)
{
    const auto rawJsonLength = static_cast<int>(jsonString.length());
    JSONCPP_STRING err;
    Json::CharReaderBuilder builder;
    const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    if (!reader->parse(jsonString.c_str(), jsonString.c_str() + rawJsonLength, &dataObj, &err)) {
        EDMLOGE("JsonSerializer::Deserialize jsonString error: %{public}s ", err.c_str());
        return false;
    }
    return true;
}

bool JsonSerializer::Serialize(const Json::Value &dataObj, std::string &jsonString)
{
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "    ";
    jsonString = Json::writeString(builder, dataObj);
    return true;
}

bool JsonSerializer::GetPolicy(MessageParcel &data, Json::Value &result)
{
    std::string jsonString = Str16ToStr8(data.ReadString16());
    return Deserialize(jsonString, result);
}

bool JsonSerializer::WritePolicy(MessageParcel &reply, Json::Value &result)
{
    std::string jsonString;
    if (!Serialize(result, jsonString)) {
        return false;
    }
    return reply.WriteString16(Str8ToStr16(jsonString));
}

bool JsonSerializer::MergePolicy(std::vector<Json::Value> &data, Json::Value &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS