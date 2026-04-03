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

#include "disallowed_bluetooth_protocols_plugin.h"

#include <cstdio>
#include <fstream>
#include "bluetooth_protocol_policy_serializer.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "directory_ex.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_os_account_manager_impl.h"
#include "func_code_utils.h"
#include "parameters.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const std::string CONFIG_PATH = "/data/service/el1/public/edm/config/system/all/bluetooth/config.json";
const std::string CONFIG_SYSTEM_ALL_DIR = "/data/service/el1/public/edm/config/system/all";
const std::string BLUETOOTH_DIR = "bluetooth";
const std::string SEPARATOR = "/";
constexpr int32_t EDM_UID = 3057;
constexpr int32_t EDM_GID = 3057;
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowedBluetoothProtocolsPlugin::GetPlugin());

void DisallowedBluetoothProtocolsPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowedBluetoothProtocolsPlugin, BluetoothProtocolPolicy>> ptr)
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_BLUETOOTH_PROTOCOLS,
        PolicyName::POLICY_DISALLOWED_BLUETOOTH_PROTOCOLS, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BluetoothProtocolPolicySerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedBluetoothProtocolsPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyDoneListener(&DisallowedBluetoothProtocolsPlugin::OnChangedPolicyDone, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&DisallowedBluetoothProtocolsPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnHandlePolicyDoneListener(&DisallowedBluetoothProtocolsPlugin::OnChangedPolicyDone,
        FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&DisallowedBluetoothProtocolsPlugin::OnAdminRemove);
}

ErrCode DisallowedBluetoothProtocolsPlugin::OnSetPolicy(BluetoothProtocolPolicy &data,
    BluetoothProtocolPolicy &currentData, BluetoothProtocolPolicy &mergeData, int32_t userId)
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin OnSetPolicy");
    
    // 参数校验：accountId需要大于等于0，协议列表不能全部为空
    if (!ValidateBluetoothProtocolPolicy(data)) {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin OnSetPolicy validate policy failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::vector<BluetoothProtocolPolicy> adminValues = {currentData, data};
    BluetoothProtocolPolicy afterHandle;
    if (!serializer->MergePolicy(adminValues, afterHandle)) {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin OnSetPolicy merge failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    
    BluetoothProtocolPolicy mergeDataFromFile;
    if (!ReadMergeDataFromFile(mergeDataFromFile)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    std::vector<BluetoothProtocolPolicy> mergeValues = {mergeData, mergeDataFromFile, afterHandle};
    BluetoothProtocolPolicy afterMerge;
    if (!serializer->MergePolicy(mergeValues, afterMerge)) {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin OnSetPolicy merge failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    currentData = afterHandle;
    mergeData = afterMerge;
    if (!WriteMergeDataToFile(afterMerge)) {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin OnSetPolicy write file failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode DisallowedBluetoothProtocolsPlugin::OnRemovePolicy(BluetoothProtocolPolicy &data,
    BluetoothProtocolPolicy &currentData, BluetoothProtocolPolicy &mergeData, int32_t userId)
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin OnRemovePolicy");
    
    // 参数校验：accountId需要大于等于0，协议列表不能全部为空
    if (!ValidateBluetoothProtocolPolicy(data)) {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin OnRemovePolicy validate policy failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    
    BluetoothProtocolPolicy afterHandle = currentData;
    
    // 从currentData中删除data中指定的协议（currentData - data）
    RemoveProtocolsFromPolicy(data.protocolDenyList, afterHandle.protocolDenyList);
    RemoveProtocolsFromPolicy(data.protocolRecDenyList, afterHandle.protocolRecDenyList);
    
    BluetoothProtocolPolicy mergeDataFromFile;
    if (!ReadMergeDataFromFile(mergeDataFromFile)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    
    // 从mergeDataFromFile中删除那些在data中存在但不在mergeData中存在的协议
    RemoveUnusedProtocolsFromFile(data.protocolDenyList, mergeData.protocolDenyList,
        mergeDataFromFile.protocolDenyList);
    RemoveUnusedProtocolsFromFile(data.protocolRecDenyList, mergeData.protocolRecDenyList,
        mergeDataFromFile.protocolRecDenyList);
    
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::vector<BluetoothProtocolPolicy> mergeValues = {mergeDataFromFile, mergeData, afterHandle};
    BluetoothProtocolPolicy afterMerge;
    if (!serializer->MergePolicy(mergeValues, afterMerge)) {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin OnRemovePolicy merge failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    
    currentData = afterHandle;
    mergeData = afterMerge;
    if (!WriteMergeDataToFile(afterMerge)) {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin OnRemovePolicy write file failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

void DisallowedBluetoothProtocolsPlugin::RemoveProtocolsFromPolicy(
    const std::map<int32_t, std::vector<std::string>> &source,
    std::map<int32_t, std::vector<std::string>> &target)
{
    for (const auto& [accountId, protocolsToRemove] : source) {
        if (target.count(accountId) == 0) {
            continue;
        }
        for (const auto &protocol : protocolsToRemove) {
            auto it = std::find(target[accountId].begin(), target[accountId].end(), protocol);
            if (it != target[accountId].end()) {
                target[accountId].erase(it);
            }
        }
    }
}

void DisallowedBluetoothProtocolsPlugin::RemoveUnusedProtocolsFromFile(
    const std::map<int32_t, std::vector<std::string>> &data,
    const std::map<int32_t, std::vector<std::string>> &mergeData,
    std::map<int32_t, std::vector<std::string>> &mergeDataFromFile)
{
    for (const auto& [accountId, protocolsInData] : data) {
        auto fileDataIt = mergeDataFromFile.find(accountId);
        if (fileDataIt == mergeDataFromFile.end()) {
            continue;
        }
        
        for (const auto &protocol : protocolsInData) {
            auto mergeDataIt = mergeData.find(accountId);
            if (mergeDataIt != mergeData.end() &&
                std::find(mergeDataIt->second.begin(), mergeDataIt->second.end(), protocol) !=
                mergeDataIt->second.end()) {
                continue;
            }
            auto it = std::find(fileDataIt->second.begin(), fileDataIt->second.end(), protocol);
            if (it != fileDataIt->second.end()) {
                fileDataIt->second.erase(it);
            }
        }
    }
}

ErrCode DisallowedBluetoothProtocolsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin OnGetPolicy");
    int32_t type = data.ReadInt32();
    int32_t accountId = data.ReadInt32();
    if (accountId < 0) {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin OnGetPolicy validate accountId failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    std::vector<int32_t> protocols;
    
    BluetoothProtocolPolicy mergeDataFromFile;
    if (!ReadMergeDataFromFile(mergeDataFromFile)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    
    if (type == BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS) {
        GetSendOnlyProtocols(mergeDataFromFile, accountId, protocols);
    } else if (type == BluetoothPolicyType::SET_DISALLOWED_PROTOCOLS_WITH_POLICY) {
        int32_t transferPolicy = data.ReadInt32();
        if (transferPolicy == static_cast<int32_t>(TransferPolicy::SEND_ONLY)) {
            GetSendOnlyProtocols(mergeDataFromFile, accountId, protocols);
        } else if (transferPolicy == static_cast<int32_t>(TransferPolicy::RECEIVE_ONLY)) {
            GetReceiveOnlyProtocols(mergeDataFromFile, accountId, protocols);
        } else if (transferPolicy == static_cast<int32_t>(TransferPolicy::RECEIVE_SEND)) {
            GetReceiveSendProtocols(mergeDataFromFile, accountId, protocols);
        }
    } else {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin::OnGetPolicy type error");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32Vector(protocols);
    return ERR_OK;
}

void DisallowedBluetoothProtocolsPlugin::ConvertProtocolListToInt(const std::vector<std::string> &protocolList,
    std::vector<int32_t> &protocols)
{
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    for (const auto &protocol : protocolList) {
        int32_t protocolInt;
        if (!serializer->StrToProtocolInt(protocol, protocolInt)) {
            continue;
        }
        protocols.push_back(protocolInt);
    }
}

void DisallowedBluetoothProtocolsPlugin::GetSendOnlyProtocols(const BluetoothProtocolPolicy &mergeDataFromFile,
    int32_t accountId, std::vector<int32_t> &protocols)
{
    auto it = mergeDataFromFile.protocolDenyList.find(accountId);
    if (it != mergeDataFromFile.protocolDenyList.end()) {
        ConvertProtocolListToInt(it->second, protocols);
    }
}

void DisallowedBluetoothProtocolsPlugin::GetReceiveOnlyProtocols(const BluetoothProtocolPolicy &mergeDataFromFile,
    int32_t accountId, std::vector<int32_t> &protocols)
{
    auto it = mergeDataFromFile.protocolRecDenyList.find(accountId);
    if (it != mergeDataFromFile.protocolRecDenyList.end()) {
        ConvertProtocolListToInt(it->second, protocols);
    }
}

void DisallowedBluetoothProtocolsPlugin::GetReceiveSendProtocols(const BluetoothProtocolPolicy &mergeDataFromFile,
    int32_t accountId, std::vector<int32_t> &protocols)
{
    std::vector<std::string> sendProtocols;
    std::vector<std::string> receiveProtocols;
    
    auto it = mergeDataFromFile.protocolDenyList.find(accountId);
    if (it != mergeDataFromFile.protocolDenyList.end()) {
        sendProtocols = it->second;
    }
    auto recvIt = mergeDataFromFile.protocolRecDenyList.find(accountId);
    if (recvIt != mergeDataFromFile.protocolRecDenyList.end()) {
        receiveProtocols = recvIt->second;
    }
    
    for (const auto &protocol : sendProtocols) {
        if (std::find(receiveProtocols.begin(), receiveProtocols.end(), protocol) != receiveProtocols.end()) {
            int32_t protocolInt;
            auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
            if (!serializer->StrToProtocolInt(protocol, protocolInt)) {
                continue;
            }
            protocols.push_back(protocolInt);
        }
    }
}

ErrCode DisallowedBluetoothProtocolsPlugin::OnAdminRemove(const std::string &adminName,
    BluetoothProtocolPolicy &policyData, BluetoothProtocolPolicy &mergeData, int32_t userId)
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin OnAdminRemove");
    if (!WriteMergeDataToFile(mergeData)) {
        EDMLOGE("DisallowedBluetoothProtocolsPlugin OnRemovePolicy write file failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    NotifyBluetoothProtocolsChanged();
    return ERR_OK;
}

void DisallowedBluetoothProtocolsPlugin::OnChangedPolicyDone(bool isGlobalChanged)
{
    if (!isGlobalChanged) {
        return;
    }
    NotifyBluetoothProtocolsChanged();
}

void DisallowedBluetoothProtocolsPlugin::NotifyBluetoothProtocolsChanged()
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin NotifyBluetoothProtocolsChanged.");
    AAFwk::Want want;
    want.SetAction(EdmConstants::EDM_CONFIG_CHANGED_EVENT);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    int32_t bluetoothUid = 1002;
    EventFwk::CommonEventPublishInfo eventInfo;
    std::vector<int32_t> subscriberUids;
    subscriberUids.push_back(bluetoothUid);
    eventInfo.SetSubscriberUid(subscriberUids);
    if (!EventFwk::CommonEventManager::PublishCommonEvent(eventData, eventInfo)) {
        EDMLOGE("NotifyBluetoothProtocolsChanged failed.");
    }
}

bool DisallowedBluetoothProtocolsPlugin::ReadMergeDataFromFile(BluetoothProtocolPolicy &mergeData)
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin::loadConfig");
    std::ifstream inFile(CONFIG_PATH, std::ios::binary);
    if (!inFile.is_open()) {
        return true;
    }
    inFile.seekg(0, std::ios::end);
    if (!inFile) {
        EDMLOGE("Failed to seek to end of file");
        return false;
    }
    std::streamsize size = inFile.tellg();
    if (size < 0) {
        EDMLOGE("Failed to get file size");
        return false;
    }
    if (size == 0) {
        return true;
    }
    inFile.seekg(0, std::ios::beg);
    if (!inFile) {
        EDMLOGE("Failed to seek to beginning of file");
        return false;
    }
    std::string jsonStr;
    jsonStr.resize(size);
    if (!inFile.read(&jsonStr[0], size)) {
        EDMLOGE("Failed to read file content");
        return false;
    }
    if (inFile.gcount() != size) {
        return false;
    }
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    if (!serializer->Deserialize(jsonStr, mergeData)) {
        EDMLOGE("Failed to deserialize JSON data");
        return false;
    }
    return true;
}

bool DisallowedBluetoothProtocolsPlugin::WriteMergeDataToFile(const BluetoothProtocolPolicy &mergeData)
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin::WriteMergeDataToFile");
    std::vector<std::string> files;
    OHOS::GetDirFiles(CONFIG_SYSTEM_ALL_DIR, files);
    if (std::find(files.begin(), files.end(), BLUETOOTH_DIR) == files.end() &&
        !CreateBluetoothConfigDir(CONFIG_SYSTEM_ALL_DIR + SEPARATOR + BLUETOOTH_DIR)) {
        EDMLOGE("Failed to create bluetooth dir");
        return false;
    }
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::string jsonStr;
    if (!serializer->Serialize(mergeData, jsonStr)) {
        EDMLOGE("Failed to serialize data to JSON");
        return false;
    }
    std::ofstream outFile(CONFIG_PATH, std::ios::binary);
    if (!outFile.is_open()) {
        EDMLOGE("Failed to open temp file for writing");
        return false;
    }
    if (!outFile.write(jsonStr.c_str(), jsonStr.size())) {
        EDMLOGE("Failed to write data to temp file");
        outFile.close();
        return false;
    }
    outFile.close();
    return true;
}

bool DisallowedBluetoothProtocolsPlugin::CreateBluetoothConfigDir(const std::string dir)
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin::CreateBluetoothConfigDir");
    if (!OHOS::ForceCreateDirectory(dir)) {
        EDMLOGE("mkdir dir failed");
        return false;
    }
    if (chown(dir.c_str(), EDM_UID, EDM_GID) != 0) {
        EDMLOGE("fail to change dir ownership");
        return false;
    }
    mode_t mode = S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH;
    if (!OHOS::ChangeModeFile(dir, mode)) {
        EDMLOGE("change mode failed, temp install dir");
        return false;
    }
    return true;
}

bool DisallowedBluetoothProtocolsPlugin::ValidateBluetoothProtocolPolicy(const BluetoothProtocolPolicy &policy)
{
    // 一定会有一个 accountId，否则就是异常场景
    // 从两个列表中找出 accountId（优先从 protocolDenyList 中获取）
    int32_t accountId = -1;
    if (!policy.protocolDenyList.empty()) {
        accountId = policy.protocolDenyList.begin()->first;
    } else if (!policy.protocolRecDenyList.empty()) {
        accountId = policy.protocolRecDenyList.begin()->first;
    } else {
        // 两个列表都为空，说明没有数据
        EDMLOGE("ValidateBluetoothProtocolPolicy: all protocol lists are empty");
        return false;
    }
    if (accountId < 0) {
        EDMLOGE("ValidateBluetoothProtocolPolicy: invalid accountId %{public}d", accountId);
        return false;
    }
    // 校验至少有一个协议列表不为空
    bool hasValidData = false;
    auto denyIt = policy.protocolDenyList.find(accountId);
    if (denyIt != policy.protocolDenyList.end() && !denyIt->second.empty()) {
        hasValidData = true;
    }
    auto recIt = policy.protocolRecDenyList.find(accountId);
    if (recIt != policy.protocolRecDenyList.end() && !recIt->second.empty()) {
        hasValidData = true;
    }
    if (!hasValidData) {
        EDMLOGE("ValidateBluetoothProtocolPolicy: all protocol lists are empty for accountId %{public}d", accountId);
        return false;
    }
    // SPP协议必须在两个列表中同时存在或同时不存在
    bool sppInDenyList = false;
    if (denyIt != policy.protocolDenyList.end()) {
        sppInDenyList = std::find(denyIt->second.begin(), denyIt->second.end(), "SPP") !=
            denyIt->second.end();
    }

    bool sppInRecDenyList = false;
    if (recIt != policy.protocolRecDenyList.end()) {
        sppInRecDenyList = std::find(recIt->second.begin(), recIt->second.end(), "SPP") !=
            recIt->second.end();
    }
    if (sppInDenyList != sppInRecDenyList) {
        EDMLOGE("ValidateBluetoothProtocolPolicy: SPP protocol must exist in both lists or neither for "
            "accountId %{public}d", accountId);
        return false;
    }
    return true;
}
} // namespace EDM
} // namespace OHOS