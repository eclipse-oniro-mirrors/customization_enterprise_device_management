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

#include "bluetooth_protocol_policy_serializer.h"

#include "cJSON.h"
#include "cjson_check.h"

namespace OHOS {
namespace EDM {
const char* const PROTOCOL_DENY_LIST = "ProtocolDenyList";
const char* const PROTOCOL_REC_DENY_LIST = "ProtocolRecDenyList";

const std::unordered_map<BtProtocol, std::string> BluetoothProtocolPolicySerializer::protocolToStrMap = {
    {BtProtocol::GATT, "GATT"},
    {BtProtocol::SPP, "SPP"},
    {BtProtocol::OPP, "OPP"}
};

const std::unordered_map<std::string, BtProtocol> BluetoothProtocolPolicySerializer::strToProtocolMap = {
    {"GATT", BtProtocol::GATT},
    {"SPP", BtProtocol::SPP},
    {"OPP", BtProtocol::OPP}
};

bool BluetoothProtocolPolicySerializer::Deserialize(const std::string &data, BluetoothProtocolPolicy &result)
{
    cJSON* root = cJSON_Parse(data.c_str());
    if (root == nullptr) {
        return true;
    }

    cJSON* denyList = cJSON_GetObjectItem(root, PROTOCOL_DENY_LIST);
    cJSON* recDenyList = cJSON_GetObjectItem(root, PROTOCOL_REC_DENY_LIST);

    if (denyList != nullptr && cJSON_IsObject(denyList)) {
        cJSON* userIdItem = denyList->child;
        while (userIdItem != nullptr) {
            if (userIdItem->string != nullptr) {
                int32_t userId = atoi(userIdItem->string);
                cJSON* protocols = userIdItem->child;
                if (protocols != nullptr && cJSON_IsArray(protocols)) {
                    cJSON* protocolItem = protocols->child;
                    while (protocolItem != nullptr) {
                        if (protocolItem->string != nullptr) {
                            result.protocolDenyList[userId].push_back(protocolItem->string);
                        }
                        protocolItem = protocolItem->next;
                    }
                }
            }
            userIdItem = userIdItem->next;
        }
    }

    if (recDenyList != nullptr && cJSON_IsObject(recDenyList)) {
        cJSON* userIdItem = recDenyList->child;
        while (userIdItem != nullptr) {
            if (userIdItem->string != nullptr) {
                int32_t userId = atoi(userIdItem->string);
                cJSON* protocols = userIdItem->child;
                if (protocols != nullptr && cJSON_IsArray(protocols)) {
                    cJSON* protocolItem = protocols->child;
                    while (protocolItem != nullptr) {
                        if (protocolItem->string != nullptr) {
                            result.protocolRecDenyList[userId].push_back(protocolItem->string);
                        }
                        protocolItem = protocolItem->next;
                    }
                }
            }
            userIdItem = userIdItem->next;
        }
    }

    cJSON_Delete(root);
    return true;
}

bool BluetoothProtocolPolicySerializer::Serialize(const BluetoothProtocolPolicy &result, std::string &data)
{
    cJSON* root = cJSON_CreateObject();

    if (!result.protocolDenyList.empty()) {
        cJSON* denyList = cJSON_CreateObject();
        for (const auto& [userId, protocols] : result.protocolDenyList) {
            if (protocols.empty()) {
                continue;
            }
            cJSON* protocolArray = cJSON_CreateArray();
            for (const std::string& protocol : protocols) {
                cJSON_AddItemToArray(protocolArray, cJSON_CreateString(protocol.c_str()));
            }
            cJSON_AddItemToObject(denyList, std::to_string(userId).c_str(), protocolArray);
        }
        cJSON_AddItemToObject(root, PROTOCOL_DENY_LIST, denyList);
    }

    if (!result.protocolRecDenyList.empty()) {
        cJSON* recDenyList = cJSON_CreateObject();
        for (const auto& [userId, protocols] : result.protocolRecDenyList) {
            if (protocols.empty()) {
                continue;
            }
            cJSON* protocolArray = cJSON_CreateArray();
            for (const std::string& protocol : protocols) {
                cJSON_AddItemToArray(protocolArray, cJSON_CreateString(protocol.c_str()));
            }
            cJSON_AddItemToObject(recDenyList, std::to_string(userId).c_str(), protocolArray);
        }
        cJSON_AddItemToObject(root, PROTOCOL_REC_DENY_LIST, recDenyList);
    }

    char* jsonStr = cJSON_Print(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return false;
    }
    data = std::string(jsonStr);
    cJSON_free(jsonStr);
    cJSON_Delete(root);
    return true;
}

bool BluetoothProtocolPolicySerializer::GetPolicy(MessageParcel &data, BluetoothProtocolPolicy &result)
{
    int32_t policyType = data.ReadInt32();
    int32_t accountId = data.ReadInt32();
    std::vector<int32_t> bluetoothProtocols;
    if (!data.ReadInt32Vector(&bluetoothProtocols)) {
        return false;
    }
    std::vector<std::string> protocolStrs;
    for (const auto &item : bluetoothProtocols) {
        std::string protocolStr;
        if (!IntToProtocolStr(item, protocolStr)) {
            return false;
        }
        protocolStrs.push_back(protocolStr);
    }
    if (policyType == BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS) {
        result.protocolDenyList[accountId] = protocolStrs;
        return true;
    } else if (policyType == BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS_WITH_POLICY) {
        int32_t transferPolicy = data.ReadInt32();
        switch (transferPolicy) {
            case static_cast<int32_t>(TransferPolicy::SEND_ONLY):
                result.protocolDenyList[accountId] = protocolStrs;
                return true;
            case static_cast<int32_t>(TransferPolicy::RECEIVE_ONLY):
                result.protocolRecDenyList[accountId] = protocolStrs;
                return true;
            case static_cast<int32_t>(TransferPolicy::RECEIVE_SEND):
                result.protocolDenyList[accountId] = protocolStrs;
                result.protocolRecDenyList[accountId] = protocolStrs;
                return true;
            default:
                return false;
        }
    } else {
        return false;
    }
}

bool BluetoothProtocolPolicySerializer::WritePolicy(MessageParcel &reply, BluetoothProtocolPolicy &result)
{
    return true;
}

bool BluetoothProtocolPolicySerializer::MergePolicy(std::vector<BluetoothProtocolPolicy> &data,
    BluetoothProtocolPolicy &result)
{
    for (const auto &dataItem : data) {
        for (const auto& [userId, protocols] : dataItem.protocolDenyList) {
            for (const std::string& protocol : protocols) {
                result.protocolDenyList[userId].push_back(protocol);
            }
        }
        for (const auto& [userId, protocols] : dataItem.protocolRecDenyList) {
            for (const std::string& protocol : protocols) {
                result.protocolRecDenyList[userId].push_back(protocol);
            }
        }
    }
    return true;
}

bool BluetoothProtocolPolicySerializer::IntToProtocolStr(int32_t value, std::string &str)
{
    if (value < static_cast<int>(BtProtocol::GATT) || value > static_cast<int>(BtProtocol::OPP)) {
        return false;
    }
    auto it = protocolToStrMap.find(static_cast<BtProtocol>(value));
    if (it != protocolToStrMap.end()) {
        str = it->second;
        return true;
    }
    return false;
}

bool BluetoothProtocolPolicySerializer::StrToProtocolInt(const std::string &str, int32_t &value)
{
    auto it = strToProtocolMap.find(str);
    if (it == strToProtocolMap.end()) {
        return false;
    }
    value = static_cast<int32_t>(it->second);
    return true;
}
} // namespace EDM
} // namespace OHOS
