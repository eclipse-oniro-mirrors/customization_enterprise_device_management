/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with License.
 * You may obtain a copy of License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bluetooth_protocol_policy_serializer.h"

#include "cJSON.h"
#include "cjson_check.h"
#include <unordered_set>

namespace OHOS {
namespace EDM {
const char* const PROTOCOL_DENY_LIST = "ProtocolDenyList";
const char* const PROTOCOL_REC_DENY_LIST = "ProtocolRecDenyList";

const std::unordered_map<BtProtocol, std::string> BluetoothProtocolPolicySerializer::protocolToStrMap = {
    {BtProtocol::GATT, BtProtocolStr::GATT},
    {BtProtocol::SPP, BtProtocolStr::SPP},
    {BtProtocol::OPP, BtProtocolStr::OPP}
};

const std::unordered_map<std::string, BtProtocol> BluetoothProtocolPolicySerializer::strToProtocolMap = {
    {BtProtocolStr::GATT, BtProtocol::GATT},
    {BtProtocolStr::SPP, BtProtocol::SPP},
    {BtProtocolStr::OPP, BtProtocol::OPP}
};

// 处理协议名称数组
void BluetoothProtocolPolicySerializer::ProcessProtocolArray(cJSON* protocolArray,
    std::vector<std::string>& protocolNames)
{
    if (!cJSON_IsArray(protocolArray)) {
        return;
    }
    
    int arraySize = cJSON_GetArraySize(protocolArray);
    for (int i = 0; i < arraySize; i++) {
        cJSON* arrayItem = cJSON_GetArrayItem(protocolArray, i);
        if (cJSON_IsString(arrayItem)) {
            protocolNames.push_back(arrayItem->valuestring);
        }
    }
}

// 处理单个协议条目（协议编号 -> 协议名称数组）
void BluetoothProtocolPolicySerializer::ProcessProtocolEntry(cJSON* entry,
    std::map<int32_t, std::vector<std::string>>& denyList)
{
    const char* protocolIdStr = entry->string;
    int32_t protocolId = std::stoi(protocolIdStr);
    
    if (!cJSON_IsArray(entry)) {
        return;
    }
    
    std::vector<std::string> protocolNames;
    ProcessProtocolArray(entry, protocolNames);
    
    if (!protocolNames.empty()) {
        denyList[protocolId] = std::move(protocolNames);
    }
}

// 解析完整的协议拒绝列表
void BluetoothProtocolPolicySerializer::ParseProtocolDenyList(cJSON* denyListObj,
    std::map<int32_t, std::vector<std::string>>& denyList)
{
    if (!cJSON_IsObject(denyListObj)) {
        return;
    }
    
    cJSON* currentItem = nullptr;
    cJSON_ArrayForEach(currentItem, denyListObj) {
        ProcessProtocolEntry(currentItem, denyList);
    }
}

void BluetoothProtocolPolicySerializer::ParseLegacyProtocolArray(cJSON* array,
    std::map<int32_t, std::vector<std::string>>& result)
{
    // array 结构: [0, 1, 2] （数字数组，表示协议枚举值）
    // 遍历数组中的每个数字，转换为协议字符串
    std::vector<std::string> protocolStrs;
    cJSON* item = nullptr;
    cJSON_ArrayForEach(item, array) {
        if (cJSON_IsNumber(item)) {
            std::string protocolStr;
            if (IntToProtocolStr(static_cast<int32_t>(item->valueint), protocolStr)) {
                protocolStrs.push_back(protocolStr);
            }
        }
    }
    if (!protocolStrs.empty()) {
        result[accountId_] = protocolStrs;
    }
}

bool BluetoothProtocolPolicySerializer::Deserialize(const std::string &data, BluetoothProtocolPolicy &result)
{
    // 支持两种JSON格式：
    // 1. 旧格式（数组）: [0, 1, 2]
    // 2. 新格式（对象）: {"ProtocolDenyList": {...}, "ProtocolRecDenyList": {...}}
    if (data.empty()) {
        return true;
    }
    cJSON* root = cJSON_Parse(data.c_str());
    if (root == nullptr) {
        return false;
    }

    if (cJSON_IsArray(root)) {
        // 解析旧格式：数字数组
        ParseLegacyProtocolArray(root, result.protocolDenyList);
    } else {
        // 解析新格式：包含ProtocolDenyList和ProtocolRecDenyList的对象
        cJSON* denyList = cJSON_GetObjectItem(root, PROTOCOL_DENY_LIST);
        cJSON* recDenyList = cJSON_GetObjectItem(root, PROTOCOL_REC_DENY_LIST);
        if (denyList != nullptr && cJSON_IsObject(denyList)) {
            ParseProtocolDenyList(denyList, result.protocolDenyList);
        }
        if (recDenyList != nullptr && cJSON_IsObject(recDenyList)) {
            ParseProtocolDenyList(recDenyList, result.protocolRecDenyList);
        }
    }
    cJSON_Delete(root);
    return true;
}

void BluetoothProtocolPolicySerializer::BuildProtocolDenyList(const std::map<int32_t,
    std::vector<std::string>>& protocolList,
    cJSON* parent, const char* key)
{
    // protocolList 结构: {100: ["GATT", "SPP"], 101: ["OPP"]}
    // 将其转换为JSON对象: {"100": ["GATT", "SPP"], "101": ["OPP"]}
    if (protocolList.empty()) {
        return;
    }
    cJSON* denyList = cJSON_CreateObject();
    for (const auto& [userId, protocols] : protocolList) {
        if (protocols.empty()) {
            continue;
        }
        // 为每个用户ID创建协议数组
        cJSON* protocolArray = cJSON_CreateArray();
        for (const std::string& protocol : protocols) {
            cJSON_AddItemToArray(protocolArray, cJSON_CreateString(protocol.c_str()));
        }
        cJSON_AddItemToObject(denyList, std::to_string(userId).c_str(), protocolArray);
    }
    cJSON_AddItemToObject(parent, key, denyList);
}

bool BluetoothProtocolPolicySerializer::Serialize(const BluetoothProtocolPolicy &result, std::string &data)
{
    // 将BluetoothProtocolPolicy结构序列化为JSON字符串
    // 输出格式: {"ProtocolDenyList": {...}, "ProtocolRecDenyList": {...}}
    cJSON* root = cJSON_CreateObject();
    if (!result.protocolDenyList.empty()) {
        BuildProtocolDenyList(result.protocolDenyList, root, PROTOCOL_DENY_LIST);
    }
    if (!result.protocolRecDenyList.empty()) {
        BuildProtocolDenyList(result.protocolRecDenyList, root, PROTOCOL_REC_DENY_LIST);
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

bool BluetoothProtocolPolicySerializer::HandleDisallowedProtocols(int32_t accountId,
    const std::vector<std::string>& protocolStrs, BluetoothProtocolPolicy& result)
{
    // 处理不带传输策略的禁用协议请求
    // 将协议列表添加到protocolDenyList（禁止发送）
    result.protocolDenyList[accountId] = protocolStrs;
    if (std::find(protocolStrs.begin(), protocolStrs.end(), BtProtocolStr::SPP) != protocolStrs.end()) {
        result.protocolRecDenyList[accountId].push_back(BtProtocolStr::SPP);
    }
    return true;
}

bool BluetoothProtocolPolicySerializer::HandleDisallowedWithPolicy(int32_t accountId,
    const std::vector<std::string>& protocolStrs, int32_t transferPolicy, BluetoothProtocolPolicy& result)
{
    // 处理带传输策略的禁用协议请求
    // 根据transferPolicy决定添加到protocolDenyList还是protocolRecDenyList
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
}

bool BluetoothProtocolPolicySerializer::GetPolicy(MessageParcel &data, BluetoothProtocolPolicy &result)
{
    // 从MessageParcel中解析策略数据
    // 数据格式: [policyType, accountId, [protocol1, protocol2, ...], transferPolicy?]
    int32_t policyType = data.ReadInt32();
    accountId_ = data.ReadInt32();
    std::vector<int32_t> bluetoothProtocols;
    if (!data.ReadInt32Vector(&bluetoothProtocols)) {
        return false;
    }
    // 将协议枚举值转换为字符串
    std::vector<std::string> protocolStrs;
    for (const auto &item : bluetoothProtocols) {
        std::string protocolStr;
        if (!IntToProtocolStr(item, protocolStr)) {
            return false;
        }
        protocolStrs.push_back(protocolStr);
    }
    // 根据策略类型调用相应的处理函数
    if (policyType == BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS) {
        return HandleDisallowedProtocols(accountId_, protocolStrs, result);
    } else if (policyType == BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS_WITH_POLICY) {
        int32_t transferPolicy = data.ReadInt32();
        return HandleDisallowedWithPolicy(accountId_, protocolStrs, transferPolicy, result);
    }
    return false;
}

bool BluetoothProtocolPolicySerializer::WritePolicy(MessageParcel &reply, BluetoothProtocolPolicy &result)
{
    return true;
}

bool BluetoothProtocolPolicySerializer::MergePolicy(std::vector<BluetoothProtocolPolicy> &data,
    BluetoothProtocolPolicy &result)
{
    for (const auto &dataItem : data) {
        // 合并发送禁止列表
        for (const auto& [userId, protocols] : dataItem.protocolDenyList) {
            for (const std::string& protocol : protocols) {
                result.protocolDenyList[userId].push_back(protocol);
            }
        }
        // 合并接收禁止列表
        for (const auto& [userId, protocols] : dataItem.protocolRecDenyList) {
            for (const std::string& protocol : protocols) {
                result.protocolRecDenyList[userId].push_back(protocol);
            }
        }
    }
    // 对合并后的协议列表进行去重
    for (auto& [userId, protocols] : result.protocolDenyList) {
        std::unordered_set<std::string> uniqueProtocols(protocols.begin(), protocols.end());
        protocols.assign(uniqueProtocols.begin(), uniqueProtocols.end());
    }
    for (auto& [userId, protocols] : result.protocolRecDenyList) {
        std::unordered_set<std::string> uniqueProtocols(protocols.begin(), protocols.end());
        protocols.assign(uniqueProtocols.begin(), uniqueProtocols.end());
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