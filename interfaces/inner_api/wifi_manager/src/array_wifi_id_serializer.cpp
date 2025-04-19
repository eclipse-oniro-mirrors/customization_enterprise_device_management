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

#include "array_wifi_id_serializer.h"
#include "cJSON.h"
#include "cjson_check.h"
#include "edm_constants.h"

namespace OHOS {
namespace EDM {

const std::string SSID = "ssid";
const std::string BSSID = "bssid";

std::vector<WifiId> ArrayWifiIdSerializer::SetUnionPolicyData(std::vector<WifiId> &data,
    std::vector<WifiId> &currentData)
{
    std::vector<WifiId> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_union(data.begin(), data.end(), currentData.begin(), currentData.end(), back_inserter(mergeData));
    return mergeData;
}

std::vector<WifiId> ArrayWifiIdSerializer::SetDifferencePolicyData(std::vector<WifiId> &data,
    std::vector<WifiId> &currentData)
{
    std::vector<WifiId> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_difference(currentData.begin(), currentData.end(), data.begin(), data.end(), back_inserter(mergeData));
    return mergeData;
}

bool ArrayWifiIdSerializer::Deserialize(const std::string &jsonString, std::vector<WifiId> &dataObj)
{
    cJSON* root = cJSON_Parse(jsonString.c_str());
    if (root == nullptr) {
        return true;
    }
    cJSON* item;
    cJSON_ArrayForEach(item, root) {
        cJSON* ssid = cJSON_GetObjectItem(item, SSID.c_str());
        cJSON* bssid = cJSON_GetObjectItem(item, BSSID.c_str());
        if (ssid == nullptr || bssid == nullptr) {
            cJSON_Delete(root);
            return false;
        }
        if (!cJSON_IsString(ssid) || !cJSON_IsString(bssid)) {
            continue;
        }
        WifiId wifiId;
        wifiId.SetSsid(ssid->valuestring);
        wifiId.SetBssid(bssid->valuestring);
        dataObj.push_back(wifiId);
    }
    cJSON_Delete(root);
    return true;
}

bool ArrayWifiIdSerializer::Serialize(const std::vector<WifiId> &dataObj, std::string &jsonString)
{
    if (dataObj.empty()) {
        return true;
    }
    cJSON* root = nullptr;
    CJSON_CREATE_ARRAY_AND_CHECK(root, false);
    for (const auto& wifiId : dataObj) {
        cJSON* item = nullptr;
        CJSON_CREATE_OBJECT_AND_CHECK_AND_CLEAR(item, false, root);
        cJSON_AddStringToObject(item, SSID.c_str(), wifiId.GetSsid().c_str());
        cJSON_AddStringToObject(item, BSSID.c_str(), wifiId.GetBssid().c_str());
        if (!cJSON_AddItemToArray(root, item)) {
            cJSON_Delete(root);
            cJSON_Delete(item);
            return false;
        }
    }
    char* jsonStr = cJSON_Print(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return false;
    }
    jsonString = std::string(jsonStr);
    cJSON_free(jsonStr);
    cJSON_Delete(root);
    return true;
}

bool ArrayWifiIdSerializer::GetPolicy(MessageParcel &data, std::vector<WifiId> &result)
{
    uint32_t size = data.ReadUint32();
    if (size > EdmConstants::WIFI_LIST_MAX_SIZE) {
        EDMLOGE("ArrayWifiIdSerializer:GetPolicy size=[%{public}u] is too large", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        WifiId wifiId;
        if (!WifiId::Unmarshalling(data, wifiId)) {
            EDMLOGE("ArrayWifiIdSerializer::GetPolicy read parcel fail");
            return false;
        }
        result.emplace_back(wifiId);
    }
    return true;
}

bool ArrayWifiIdSerializer::WritePolicy(MessageParcel &reply, std::vector<WifiId> &result)
{
    return true;
}

bool ArrayWifiIdSerializer::MergePolicy(std::vector<std::vector<WifiId>> &data,
    std::vector<WifiId> &result)
{
    std::set<WifiId> stData;
    for (const auto &dataItem : data) {
        for (const auto &item : dataItem) {
            stData.insert(item);
        }
    }
    result.assign(stData.begin(), stData.end());
    return true;
}

ErrCode ArrayWifiIdSerializer::QueryWifiListPolicy(const std::string &policyData, MessageParcel &reply)
{
    std::vector<WifiId> wifiIds;
    if (!Deserialize(policyData, wifiIds)) {
        EDMLOGE("QueryWifiListPolicy Deserialize error");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteUint32(wifiIds.size());
    for (const auto &wifiId : wifiIds) {
        if (!wifiId.Marshalling(reply)) {
            EDMLOGE("QueryWifiListPolicy : write parcel failed!");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS