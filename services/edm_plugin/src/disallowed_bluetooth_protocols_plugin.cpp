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
    
    BluetoothProtocolPolicy afterHandle = currentData;
    if (data.protocolDenyList.count(userId) > 0) {
        for (const auto &protocol : data.protocolDenyList[userId]) {
            auto it = std::find(afterHandle.protocolDenyList[userId].begin(),
                afterHandle.protocolDenyList[userId].end(), protocol);
            if (it != afterHandle.protocolDenyList[userId].end()) {
                afterHandle.protocolDenyList[userId].erase(it);
            }
        }
    }
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::vector<BluetoothProtocolPolicy> mergeValues = {mergeData, afterHandle};
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

ErrCode DisallowedBluetoothProtocolsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("DisallowedBluetoothProtocolsPlugin OnGetPolicy");
    int32_t accountId = data.ReadInt32();
    
    BluetoothProtocolPolicy mergeDataFromFile;
    if (!ReadMergeDataFromFile(mergeDataFromFile)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    
    auto serializer = BluetoothProtocolPolicySerializer::GetInstance();
    std::vector<int32_t> protocols;
    if (mergeDataFromFile.protocolDenyList.count(accountId) > 0) {
        for (const auto &protocol : mergeDataFromFile.protocolDenyList[accountId]) {
            int32_t protocolInt;
            if (!serializer->StrToProtocolInt(protocol, protocolInt)) {
                continue;
            }
            protocols.push_back(protocolInt);
        }
    }
    
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32Vector(protocols);
    return ERR_OK;
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
} // namespace EDM
} // namespace OHOS