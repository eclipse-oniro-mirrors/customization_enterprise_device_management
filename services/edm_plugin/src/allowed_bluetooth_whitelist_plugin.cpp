/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "allowed_bluetooth_whitelist_plugin.h"

#include "array_string_serializer.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(AllowedBluetoothWhitelistPlugin::GetPlugin());
const char *const PERSIST_BLUETOOTH_CONTROL = "persist.edm.prohibit_bluetooth";
const char *const BLUETOOTH_WHITELIST_CHANGED_EVENT = "com.ohos.edm.bluetoothwhitelistchanged";

void AllowedBluetoothWhitelistPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<AllowedBluetoothWhitelistPlugin, std::vector<std::string>>> ptr)

{
    EDMLOGI("AllowedBluetoothWhitelistPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::ALLOWED_BLUETOOTH_WHITELIST, "allowed_bluetooth_whitelist",
                       "ohos.permission.ENTERPRISE_MANAGE_BLUETOOTH", IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
                       true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&AllowedBluetoothWhitelistPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyDoneListener(&AllowedBluetoothWhitelistPlugin::OnChangedPolicyDone, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&AllowedBluetoothWhitelistPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnHandlePolicyDoneListener(&AllowedBluetoothWhitelistPlugin::OnChangedPolicyDone, FuncOperateType::REMOVE);
}

ErrCode AllowedBluetoothWhitelistPlugin::OnSetPolicy(std::vector<std::string> &data,
                                                     std::vector<std::string> &currentData, int32_t userId)
{
    EDMLOGI("AllowedBluetoothWhitelistPlugin OnSetPolicy userId = %{public}d", userId);
    bool isDisabled = system::GetBoolParameter(PERSIST_BLUETOOTH_CONTROL, false);
    if (isDisabled) {
        EDMLOGE("AllowedBluetoothWhitelistPlugin OnSetPolicy failed, because bluetooth disabled:");
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    if (data.empty()) {
        EDMLOGW("AllowedBluetoothWhitelistPlugin OnSetPolicy data is empty:");
        return ERR_OK;
    }

    std::vector<std::string> mergeData = ArrayStringSerializer::GetInstance()->SetUnionPolicyData(data, currentData);
    if (mergeData.size() > EdmConstants::BLUETOOTH_WHITELIST_MAX_SIZE) {
        EDMLOGE("AllowedBluetoothWhitelistPlugin OnSetPolicy data is too large:");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    currentData = mergeData;
    return ERR_OK;
}

ErrCode AllowedBluetoothWhitelistPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("AllowedBluetoothWhitelistPlugin OnGetPolicy policyData : %{public}s, userId : %{public}d",
            policyData.c_str(), userId);
    std::vector<std::string> whitelist;
    pluginInstance_->serializer_->Deserialize(policyData, whitelist);
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(whitelist.size());
    reply.WriteStringVector(whitelist);
    return ERR_OK;
}

ErrCode AllowedBluetoothWhitelistPlugin::OnRemovePolicy(std::vector<std::string> &data,
    std::vector<std::string> &currentData, int32_t userId)
{
    EDMLOGD("AllowedBluetoothWhitelistPlugin OnRemovePolicy userId : %{public}d:", userId);
    if (data.empty()) {
        EDMLOGW("AllowedBluetoothWhitelistPlugin OnRemovePolicy data is empty:");
        return ERR_OK;
    }
    std::vector<std::string> mergeData =
        ArrayStringSerializer::GetInstance()->SetDifferencePolicyData(data, currentData);
    currentData = mergeData;
    return ERR_OK;
}

void AllowedBluetoothWhitelistPlugin::OnChangedPolicyDone(bool isGlobalChanged)
{
    if (!isGlobalChanged) {
        return;
    }
    NotifyBluetoothWhitelistChanged();
}

void AllowedBluetoothWhitelistPlugin::NotifyBluetoothWhitelistChanged()
{
    EDMLOGD("AllowedBluetoothWhitelistPlugin NotifyBluetoothWhitelistChanged.");
    AAFwk::Want want;
    want.SetAction(BLUETOOTH_WHITELIST_CHANGED_EVENT);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    if (!EventFwk::CommonEventManager::PublishCommonEvent(eventData)) {
        EDMLOGE("NotifyBluetoothWhitelistChanged failed.");
    }
}

} // namespace EDM
} // namespace OHOS