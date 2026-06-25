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
 
#include "switch_param_serializer.h"

#include "edm_json_builder.h"
 
namespace OHOS {
namespace EDM {
const std::string NEARLINK = "NEARLINK";
const std::string BLUETOOTH = "BLUETOOTH";
const std::string WIFI = "WIFI";
const std::string NFC = "NFC";
const std::string UNKNOWN = "UNKNOWN";
const std::string ON = "ON";
const std::string OFF = "OFF";
const std::string FORCE_ON = "FORCE_ON";

std::string SwitchParamSerializer::SwitchKeyToString(SwitchKey key)
{
    switch (key) {
        case SwitchKey::NEARLINK:
            return NEARLINK;
        case SwitchKey::BLUETOOTH:
            return BLUETOOTH;
        case SwitchKey::WIFI:
            return WIFI;
        case SwitchKey::NFC:
            return NFC;
        default:
            return UNKNOWN;
    }
}

std::string SwitchParamSerializer::SwitchStatusToString(SwitchStatus status)
{
    switch (status) {
        case SwitchStatus::ON:
            return ON;
        case SwitchStatus::OFF:
            return OFF;
        case SwitchStatus::FORCE_ON:
            return FORCE_ON;
        default:
            return UNKNOWN;
    }
}

SwitchKey SwitchParamSerializer::StringToSwitchKey(const std::string& str)
{
    if (str == NEARLINK) {
        return SwitchKey::NEARLINK;
    }
    if (str == BLUETOOTH) {
        return SwitchKey::BLUETOOTH;
    }
    if (str == WIFI) {
        return SwitchKey::WIFI;
    }
    if (str == NFC) {
        return SwitchKey::NFC;
    }
    return SwitchKey::UNKNOWN;
}

SwitchStatus SwitchParamSerializer::StringToSwitchStatus(const std::string& str)
{
    if (str == ON) {
        return SwitchStatus::ON;
    }
    if (str == OFF) {
        return SwitchStatus::OFF;
    }
    if (str == FORCE_ON) {
        return SwitchStatus::FORCE_ON;
    }
    return SwitchStatus::UNKNOWN;
}

bool SwitchParamSerializer::Deserialize(const std::string &jsonString, std::vector<SwitchParam> &config)
{
    if (jsonString.empty()) {
        EDMLOGW("SwitchParamSerializer::Deserialize jsonString.empty()");
        return true;
    }

    cJSON* root = cJSON_Parse(jsonString.c_str());
    if (root == nullptr) {
        return false;
    }
    if (!cJSON_IsArray(root)) {
        EDMLOGE("SwitchParamSerializer::Deserialize cJSON_IsArray!");
        cJSON_Delete(root);
        return false;
    }
    config.clear();
    int array_size = cJSON_GetArraySize(root);
    for (int i = 0; i < array_size; ++i) {
        cJSON* item = cJSON_GetArrayItem(root, i);
        if (item == nullptr || !cJSON_IsObject(item)) {
            continue;
        }

        SwitchParam param;
        cJSON* key_item = cJSON_GetObjectItem(item, "key");
        if (key_item != nullptr && cJSON_IsString(key_item)) {
            param.key = StringToSwitchKey(key_item->valuestring);
        }

        cJSON* status_item = cJSON_GetObjectItem(item, "status");
        if (status_item != nullptr && cJSON_IsString(status_item)) {
            param.status = StringToSwitchStatus(status_item->valuestring);
        }
        config.push_back(param);
    }
    cJSON_Delete(root);
    return true;
}
 
bool SwitchParamSerializer::Serialize(const std::vector<SwitchParam> &config, std::string &jsonString)
{
    cJSON* root = cJSON_CreateArray();
    if (root == nullptr) {
        return false;
    }
    
    for (const auto& param : config) {
        cJSON* item = cJSON_CreateObject();
        if (item == nullptr) {
            cJSON_Delete(root);
            return false;
        }
        
        cJSON_AddStringToObject(item, "key", SwitchKeyToString(param.key).c_str());
        cJSON_AddStringToObject(item, "status", SwitchStatusToString(param.status).c_str());
        cJSON_AddItemToArray(root, item);
    }
    
    char* json_str = cJSON_Print(root);
    jsonString = json_str ? json_str : "";
    
    cJSON_Delete(root);
    if (json_str) {
        cJSON_free(json_str);
    }

    return true;
}
 
bool SwitchParamSerializer::GetPolicy(MessageParcel &data, std::vector<SwitchParam> &result)
{
    int32_t key = data.ReadInt32();
    SwitchParam param;
    if (key >= static_cast<int32_t>(SwitchKey::NEARLINK) && key <= static_cast<int32_t>(SwitchKey::NFC)) {
        param.key = static_cast<SwitchKey>(key);
    }
    
    int32_t status = data.ReadInt32();
    EDMLOGI("SwitchParamSerializer::GetPolicy status:%{public}d", status);
    if (status >= static_cast<int32_t>(SwitchStatus::ON) && status <= static_cast<int32_t>(SwitchStatus::FORCE_ON)) {
        param.status = static_cast<SwitchStatus>(status);
    }
    result.push_back(param);
    return true;
}
 
bool SwitchParamSerializer::WritePolicy(MessageParcel &reply, std::vector<SwitchParam> &result)
{
    if (result.size() <= 0) {
        EDMLOGE("SwitchParamSerializer::WritePolicy result is empty");
        return false;
    }
    SwitchParam param = result[0];
    reply.WriteInt32(static_cast<int32_t>(param.key));
    reply.WriteInt32(static_cast<int32_t>(param.status));
    return true;
}
 
bool SwitchParamSerializer::MergePolicy(std::vector<std::vector<SwitchParam>> &data, std::vector<SwitchParam> &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS