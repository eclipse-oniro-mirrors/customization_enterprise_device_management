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
 
#include "set_switch_status_plugin.h"

#ifdef NFC_EDM_ENABLE
#include "nfc_controller.h"
#endif
#include "parameters.h"
#include "wifi_device.h"

#include "edm_ipc_interface_code.h"
#include "edm_json_builder.h"
#include "external_manager_factory.h"
#include "iadmin_manager.h"
#include "iedm_bluetooth_manager.h"
#include "iextra_policy_notification.h"
#include "ipc_skeleton.h"
#include "ipolicy_manager.h"
#include "iplugin_manager.h"
#include "os_account_manager.h"
#include "override_interface_name.h"

namespace OHOS {
namespace EDM {
const std::string MDM_BLUETOOTH_PROP = "persist.edm.prohibit_bluetooth";
const std::string MDM_WIFI_PROP = "persist.edm.wifi_enable";
const std::string PARAM_FORCE_OPEN_WIFI = "persist.edm.force_open_wifi";
const std::string PARAM_FORCE_ENABLE_BLUETOOTH = "persist.edm.force_enable_bluetooth";
#ifdef NFC_EDM_ENABLE
const std::string PARAM_FORCE_ENABLE_NFC = "persist.edm.force_enable_nfc";
const std::string PARAM_EDM_NFC_DISABLE = "persist.edm.nfc_disable";
#endif
const int32_t MIN_ADMIN_NUMBER = 1;
 
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetSwitchStatusPlugin::GetPlugin());
 
void SetSwitchStatusPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetSwitchStatusPlugin,
    std::vector<SwitchParam>>> ptr)
{
    EDMLOGI("SetSwitchStatusPlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS);
    typePermissions.emplace(IPlugin::PermissionType::BYOD_DEVICE_ADMIN,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::SET_SWITCH_STATUS, PolicyName::POLICY_SET_SWITCH_STATUS, config, true);
    ptr->SetSerializer(SwitchParamSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetSwitchStatusPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&SetSwitchStatusPlugin::OnAdminRemove);
}

bool SetSwitchStatusPlugin::IsByodAdmin()
{
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    std::string bundleName =
        std::make_shared<ExternalManagerFactory>()->CreateAccessTokenManager()->GetHapTokenBundleName(tokenId);
    int32_t currentId = 0;
    if (FAILED(AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(IPCSkeleton::GetCallingUid(), currentId))) {
        EDMLOGE("SetSwitchStatusPlugin::IsByodAdmin get userId failed.");
        return false;
    }
    auto adminType = IAdminManager::GetInstance()->GetAdminTypeByName(bundleName, currentId);
    return adminType == AdminType::BYOD;
}
 
ErrCode SetSwitchStatusPlugin::OnSetPolicy(std::vector<SwitchParam> &paramVec, MessageParcel &reply)
{
    int32_t ret = ERR_OK;
    if (paramVec.size() <= 0) {
        EDMLOGW("SetSwitchStatusPlugin::OnSetPolicy paramVec size is abnormally");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    SwitchParam param = paramVec[0];
    EDMLOGI("SetSwitchStatusPlugin OnSetPolicy %{public}d, %{public}d",
        static_cast<int32_t>(param.key), static_cast<int32_t>(param.status));
    if (param.status == SwitchStatus::FORCE_ON && IsByodAdmin()) {
        EDMLOGE("SetSwitchStatusPlugin::OnSetPolicy failed, because is ByodAdmin and force on");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    switch (param.key) {
        case SwitchKey::BLUETOOTH:
            ret = OnSetBluetoothStatus(param.status);
            break;
        case SwitchKey::WIFI:
            ret = OnSetWifiStatus(param.status);
            break;
#ifdef NFC_EDM_ENABLE
        case SwitchKey::NFC:
            ret = OnSetNFCStatus(param.status);
            break;
#endif
        default:
            ret = EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    reply.WriteInt32(ret);
    if (ret == EdmReturnErrCode::INTERFACE_UNSUPPORTED) {
        SwitchParamSerializer::GetInstance()->WritePolicy(reply, paramVec);
    }
    if (ret == ERR_OK) {
        std::string params = EdmJsonBuilder()
            .Add("key", static_cast<int32_t>(param.key))
            .Add("status", static_cast<int32_t>(param.status))
            .Build();
        IExtraPolicyNotification::GetInstance()->NotifyPolicyChanged(
            OverrideInterfaceName::DeviceSettings::SET_SWITCH_STATUS, params);
    }
    return ret;
}

// LCOV_EXCL_START
ErrCode SetSwitchStatusPlugin::OnSetNFCStatus(SwitchStatus status)
{
#ifdef NFC_EDM_ENABLE
    EDMLOGI("SetSwitchStatusPlugin OnSetNFCStatus in");
    ErrCode ret = ERR_OK;
    if (IsByodAdmin()) {
        EDMLOGE("SetSwitchStatusPlugin::OnSetNFCStatus failed, because is ByodAdmin");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (system::GetBoolParameter(PARAM_EDM_NFC_DISABLE, false)) {
        EDMLOGE("SetSwitchStatusPlugin OnSetNFCStatus on failed, because nfc has disabled");
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }
    if (status == SwitchStatus::ON) {
        system::SetParameter(PARAM_FORCE_ENABLE_NFC, "false");
        ret = NFC::KITS::NfcController::GetInstance().TurnOn();
    } else if (status == SwitchStatus::OFF) {
        system::SetParameter(PARAM_FORCE_ENABLE_NFC, "false");
        ret = NFC::KITS::NfcController::GetInstance().TurnOff();
    } else if (status == SwitchStatus::FORCE_ON) {
        if (system::GetBoolParameter(PARAM_FORCE_ENABLE_NFC, false)) {
            EDMLOGI("SetSwitchStatusPlugin OnSetNFCStatus nfc has force enabled");
            return ERR_OK;
        }
        system::SetParameter(PARAM_FORCE_ENABLE_NFC, "true");
        ret = NFC::KITS::NfcController::GetInstance().TurnOn();
    } else {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (ret != ERR_OK) {
        EDMLOGE("SetSwitchStatusPlugin:OnSetBluetoothStatus send request fail. %{public}d", ret);
        return EdmReturnErrCode::SWITCH_STATUS_FAILED;
    }
    return ERR_OK;
#else
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
ErrCode SetSwitchStatusPlugin::OnSetBluetoothStatus(SwitchStatus status)
{
    if (system::GetBoolParameter(MDM_BLUETOOTH_PROP, false)) {
        EDMLOGE("SetSwitchStatusPlugin OnSetBluetoothStatus failed, because bluetooth disabled");
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }
    bool ret = false;
    if (status == SwitchStatus::ON) {
        system::SetParameter(PARAM_FORCE_ENABLE_BLUETOOTH, "false");
        ret = IEdmBluetoothManager::GetInstance()->EnableBle();
    } else if (status == SwitchStatus::OFF) {
        system::SetParameter(PARAM_FORCE_ENABLE_BLUETOOTH, "false");
        ret = IEdmBluetoothManager::GetInstance()->DisableBt();
    } else if (status == SwitchStatus::FORCE_ON) {
        return ForceEnableBluetooth();
    } else {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (!ret) {
        EDMLOGE("SetSwitchStatusPlugin:OnSetBluetoothStatus send request fail. %{public}d", ret);
    }
    return ERR_OK;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
ErrCode SetSwitchStatusPlugin::OnSetWifiStatus(SwitchStatus status)
{
    if (system::GetBoolParameter(MDM_WIFI_PROP, false)) {
        EDMLOGE("SetSwitchStatusPlugin OnSetWifiStatus failed, because wifi disabled");
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }
    if (!system::SetParameter(PARAM_FORCE_OPEN_WIFI, "false")) {
        EDMLOGE("SetSwitchStatusPlugin:OnSetWifiStatus SetParameter fail. ");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::shared_ptr<Wifi::WifiDevice> devicePtr = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    if (devicePtr == nullptr) {
        EDMLOGE("SetSwitchStatusPlugin:OnSetWifiStatus WifiDevice null");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = Wifi::WIFI_OPT_SUCCESS;
    if (status == SwitchStatus::ON) {
        ret = devicePtr->EnableWifi();
    } else if (status == SwitchStatus::OFF) {
        ret = devicePtr->DisableWifi();
    } else {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (ret != Wifi::WIFI_OPT_SUCCESS) {
        EDMLOGE("SetSwitchStatusPlugin:OnSetWifiStatus send request fail. %{public}d", ret);
    }
    return ERR_OK;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
ErrCode SetSwitchStatusPlugin::ForceEnableBluetooth()
{
    if (system::GetBoolParameter(PARAM_FORCE_ENABLE_BLUETOOTH, false)) {
        return ERR_OK;
    }
    bool ret = false;
    ret = IEdmBluetoothManager::GetInstance()->EnableBle();
    if (!ret || !system::SetParameter(PARAM_FORCE_ENABLE_BLUETOOTH, "true")) {
        EDMLOGE("SetSwitchStatusPlugin:ForceEnableBluetooth send request fail or SetParameter fail.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return ERR_OK;
}
// LCOV_EXCL_STOP

ErrCode SetSwitchStatusPlugin::OnAdminRemove(const std::string &adminName, std::vector<SwitchParam> &dataVec,
    std::vector<SwitchParam> &mergeData, int32_t userId)
{
    std::unordered_map<std::string, std::string> adminListMap;
    auto policyManager = IPolicyManager::GetInstance();
    policyManager->GetAdminByPolicyName(PolicyName::POLICY_SET_SWITCH_STATUS,
        adminListMap, userId);
    if (adminListMap.size() > MIN_ADMIN_NUMBER) {
        EDMLOGI("SetSwitchStatusPlugin OnAdminRemove has other admin");
        return ERR_OK;
    }
    if (dataVec.size() <= 0) {
        EDMLOGW("OnAdminRemove data size is abnormally");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    SwitchParam data = dataVec[0];
    switch (data.key) {
        case SwitchKey::BLUETOOTH:
            system::SetParameter(PARAM_FORCE_ENABLE_BLUETOOTH, "false");
            break;
        case SwitchKey::WIFI:
            system::SetParameter(PARAM_FORCE_OPEN_WIFI, "false");
            break;
#ifdef NFC_EDM_ENABLE
        case SwitchKey::NFC:
            system::SetParameter(PARAM_FORCE_ENABLE_NFC, "false");
            break;
#endif
        default:
            break;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS