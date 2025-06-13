/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "plugin_policy_reader.h"

#ifdef BLUETOOTH_EDM_ENABLE
#include "allowed_bluetooth_devices_query.h"
#include "disallowed_bluetooth_devices_query.h"
#include "disable_bluetooth_query.h"
#endif

#ifdef USB_SERVICE_EDM_ENABLE
#include "allowed_usb_devices_query.h"
#include "disable_usb_query.h"
#endif

#ifdef USERIAM_EDM_ENABLE
#include "fingerprint_auth_query.h"
#include "password_policy.h"
#include "password_policy_query.h"
#include "password_policy_serializer.h"
#endif

#ifdef PASTEBOARD_EDM_ENABLE
#include "clipboard_policy.h"
#include "clipboard_policy_query.h"
#include "clipboard_policy_serializer.h"
#endif

#ifdef CAMERA_FRAMEWORK_EDM_ENABLE
#include "disable_camera_query.h"
#endif

#ifdef AUDIO_FRAMEWORK_EDM_ENABLE
#include "disable_hdc_query.h"
#include "disable_microphone_query.h"
#include "disable_printer_query.h"
#endif

#ifdef OS_ACCOUNT_EDM_ENABLE
#include "disallow_add_local_account_query.h"
#endif

#ifdef ABILITY_RUNTIME_EDM_ENABLE
#include "disallowed_running_bundles_query.h"
#endif

#ifdef LOCATION_EDM_ENABLE
#include "location_policy_query.h"
#endif

#ifdef WIFI_EDM_ENABLE
#include "allowed_wifi_list_query.h"
#include "array_wifi_id_serializer.h"
#include "disallowed_wifi_list_query.h"
#include "set_wifi_disabled_query.h"
#endif

#ifdef USB_STORAGE_SERVICE_EDM_ENABLE
#include "usb_read_only_query.h"
#endif

#ifdef COMMON_EVENT_SERVICE_EDM_ENABLE
#include "set_browser_policies_query.h"
#endif

#ifdef SMS_EDM_ENABLE
#include "disallowed_sms_query.h"
#endif

#ifdef MMS_EDM_ENABLE
#include "disallowed_mms_query.h"
#endif

#ifdef BACKUP_AND_RESTORE_EDM_ENABLE
#include "disable_backup_and_restore_query.h"
#endif

#ifdef APN_EDM_ENABLE
#include "disallow_modify_apn_query.h"
#endif

#ifdef MOBILE_DATA_ENABLE
#include "disallowed_mobile_data_query.h"
#endif

#ifdef SAMBA_EDM_ENABLE
#include "disable_samba_client_query.h"
#include "disable_samba_server_query.h"
#endif

#ifdef POWER_MANAGER_EDM_ENABLE
#include "disallow_power_long_press_query.h"
#endif

#ifdef NFC_EDM_ENABLE
#include "disallowed_nfc_query.h"
#endif

#ifdef FEATURE_PC_ONLY
#include "disallow_modify_ethernet_ip_query.h"
#include "get_auto_unlock_after_reboot_query.h"
#endif

#ifdef NETMANAGER_EXT_EDM_ENABLE
#include "disallow_vpn_query.h"
#endif

#include "allowed_install_bundles_query.h"
#include "disable_maintenance_mode_query.h"
#include "disable_mtp_client_query.h"
#include "disable_mtp_server_query.h"
#include "disable_remote_desk_query.h"
#include "disable_remote_diagnosis_query.h"
#include "disable_set_biometrics_and_screenLock_query.h"
#include "disable_user_mtp_client_query.h"
#include "disallow_modify_datetime_query.h"
#include "disallowed_install_bundles_query.h"
#include "disallowed_tethering_query.h"
#include "disallowed_uninstall_bundles_query.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "get_device_encryption_status_query.h"
#include "get_display_version_query.h"
#include "get_security_patch_tag_query.h"
#include "inactive_user_freeze_query.h"
#include "installed_bundle_info_list_query.h"
#include "is_app_kiosk_allowed_query.h"
#include "ntp_server_query.h"
#include "parameters.h"
#include "snapshot_skip_query.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<PluginPolicyReader> PluginPolicyReader::instance_ = nullptr;
std::once_flag PluginPolicyReader::flag_;

std::shared_ptr<PluginPolicyReader> PluginPolicyReader::GetInstance()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<PluginPolicyReader>();
        }
    });
    return instance_;
}

ErrCode PluginPolicyReader::GetPolicyByCode(std::shared_ptr<PolicyManager> policyManager, uint32_t funcCode,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    FuncCodeUtils::PrintFuncCode(funcCode);
    FuncFlag flag = FuncCodeUtils::GetSystemFlag(funcCode);
    if (flag != FuncFlag::POLICY_FLAG) {
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    std::uint32_t code = FuncCodeUtils::GetPolicyCode(funcCode);
    return GetPolicyByCodeInner(policyManager, code, data, reply, userId);
}

ErrCode PluginPolicyReader::GetPolicyByCodeInner(std::shared_ptr<PolicyManager> policyManager, uint32_t code,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    EDMLOGI("PluginPolicyReader query policy ::code %{public}u", code);
    std::shared_ptr<IPolicyQuery> obj;
    ErrCode ret = GetPolicyQuery(obj, code);
    EDMLOGI("GetPolicyQuery errcode = %{public}d", ret);
    if (obj == nullptr) {
        EDMLOGI("GetPolicyQuery obj is null, query from plugin");
        return ret;
    }
    return obj->GetPolicy(policyManager, code, data, reply, userId);
}

ErrCode PluginPolicyReader::GetPolicyQuery(std::shared_ptr<IPolicyQuery> &obj, uint32_t code)
{
    switch (code) {
        case EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES:
#ifdef BLUETOOTH_EDM_ENABLE
            obj = std::make_shared<AllowedBluetoothDevicesQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::ALLOWED_INSTALL_BUNDLES:
            obj = std::make_shared<AllowedInstallBundlesQuery>();
            return ERR_OK;
        case EdmInterfaceCode::ALLOWED_USB_DEVICES:
#ifdef USB_SERVICE_EDM_ENABLE
            obj = std::make_shared<AllowedUsbDevicesQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::CLIPBOARD_POLICY:
#ifdef PASTEBOARD_EDM_ENABLE
            obj = std::make_shared<ClipboardPolicyQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISABLE_BLUETOOTH:
#ifdef BLUETOOTH_EDM_ENABLE
            obj = std::make_shared<DisableBluetoothQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISABLE_CAMERA:
#ifdef CAMERA_FRAMEWORK_EDM_ENABLE
            obj = std::make_shared<DisableCameraQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISABLE_BACKUP_AND_RESTORE:
#ifdef BACKUP_AND_RESTORE_EDM_ENABLE
            obj = std::make_shared<DisableBackupAndRestoreQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        default:
            break;
    }
    return GetPolicyQueryFirst(obj, code);
}

ErrCode PluginPolicyReader::GetPolicyQueryFirst(std::shared_ptr<IPolicyQuery> &obj, uint32_t code)
{
    switch (code) {
        case EdmInterfaceCode::DISABLED_HDC:
#ifdef AUDIO_FRAMEWORK_EDM_ENABLE
            obj = std::make_shared<DisableHdcQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISABLE_MICROPHONE:
#ifdef AUDIO_FRAMEWORK_EDM_ENABLE
            obj = std::make_shared<DisableMicrophoneQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISABLED_PRINTER:
#ifdef AUDIO_FRAMEWORK_EDM_ENABLE
            obj = std::make_shared<DisablePrinterQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISABLE_USB:
#ifdef USB_SERVICE_EDM_ENABLE
            obj = std::make_shared<DisableUsbQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISALLOW_ADD_LOCAL_ACCOUNT:
#ifdef OS_ACCOUNT_EDM_ENABLE
            obj = std::make_shared<DisallowAddLocalAccountQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISALLOW_MODIFY_DATETIME:
            obj = std::make_shared<DisallowModifyDateTimeQuery>();
            return ERR_OK;
        case EdmInterfaceCode::DISALLOWED_INSTALL_BUNDLES:
            obj = std::make_shared<DisallowedInstallBundlesQuery>();
            return ERR_OK;
        default:
            break;
    }
    return GetPolicyQuerySecond(obj, code);
}

ErrCode PluginPolicyReader::GetPolicyQuerySecond(std::shared_ptr<IPolicyQuery> &obj, uint32_t code)
{
    switch (code) {
        case EdmInterfaceCode::DISALLOW_RUNNING_BUNDLES:
#ifdef ABILITY_RUNTIME_EDM_ENABLE
            obj = std::make_shared<DisallowedRunningBundlesQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISALLOWED_TETHERING:
            obj = std::make_shared<DisallowedThtheringQuery>();
            return ERR_OK;
        case EdmInterfaceCode::DISALLOWED_UNINSTALL_BUNDLES:
            obj = std::make_shared<DisallowedUninstallBundlesQuery>();
            return ERR_OK;
        case EdmInterfaceCode::FINGERPRINT_AUTH:
#ifdef USERIAM_EDM_ENABLE
            obj = std::make_shared<FingerprintAuthQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::GET_DEVICE_ENCRYPTION_STATUS:
            obj = std::make_shared<GetDeviceEncryptionStatusQuery>();
            return ERR_OK;
        case EdmInterfaceCode::GET_DISPLAY_VERSION:
            obj = std::make_shared<GetDisplayVersionQuery>();
            return ERR_OK;
        case EdmInterfaceCode::GET_SECURITY_PATCH_TAG:
            obj = std::make_shared<GetSecurityPatchTagQuery>();
            return ERR_OK;
        case EdmInterfaceCode::INACTIVE_USER_FREEZE:
            obj = std::make_shared<InactiveUserFreezeQuery>();
            return ERR_OK;
        case EdmInterfaceCode::LOCATION_POLICY:
#ifdef LOCATION_EDM_ENABLE
            obj = std::make_shared<LocationPolicyQuery>();
            break;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::NTP_SERVER:
            obj = std::make_shared<NTPServerQuery>();
            return ERR_OK;
    }
    return GetPolicyQueryThird(obj, code);
}

ErrCode PluginPolicyReader::GetPolicyQueryThird(std::shared_ptr<IPolicyQuery> &obj, uint32_t code)
{
    switch (code) {
        case EdmInterfaceCode::PASSWORD_POLICY:
#ifdef USERIAM_EDM_ENABLE
            obj = std::make_shared<PasswordPolicyQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISABLE_WIFI:
#ifdef WIFI_EDM_ENABLE
            obj = std::make_shared<SetWifiDisabledQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::SNAPSHOT_SKIP:
            obj = std::make_shared<SnapshotSkipQuery>();
            return ERR_OK;
        case EdmInterfaceCode::USB_READ_ONLY:
#ifdef USB_STORAGE_SERVICE_EDM_ENABLE
            obj = std::make_shared<UsbReadOnlyQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::SET_BROWSER_POLICIES:
#ifdef COMMON_EVENT_SERVICE_EDM_ENABLE
            obj = std::make_shared<SetBrowserPoliciesQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISABLE_MTP_CLIENT:
            obj = std::make_shared<DisableMtpClientQuery>();
            return ERR_OK;
        case EdmInterfaceCode::DISABLE_MTP_SERVER:
            obj = std::make_shared<DisableMtpServerQuery>();
            return ERR_OK;
        case EdmInterfaceCode::DISABLE_REMOTE_DESK:
            obj = std::make_shared<DisableRemoteDeskQuery>();
            return ERR_OK;
        case EdmInterfaceCode::DISABLE_REMOTE_DIAGNOSIS:
            obj = std::make_shared<DisableRemoteDiagnosisQuery>();
            return ERR_OK;
        case EdmInterfaceCode::DISABLE_USER_MTP_CLIENT:
            obj = std::make_shared<DisableUserMtpClientQuery>();
            return ERR_OK;
        case EdmInterfaceCode::DISABLE_MAINTENANCE_MODE:
            obj = std::make_shared<DisableMaintenanceModeQuery>();
            return ERR_OK;
        default:
            break;
    }
    return GetPolicyQueryFourth(obj, code);
}

ErrCode PluginPolicyReader::GetPolicyQueryFourth(std::shared_ptr<IPolicyQuery> &obj, uint32_t code)
{
    switch (code) {
        case EdmInterfaceCode::IS_APP_KIOSK_ALLOWED:
            obj = std::make_shared<IsAppKioskAllowedQuery>();
            return ERR_OK;
        case EdmInterfaceCode::DISALLOWED_SMS:
#ifdef SMS_EDM_ENABLE
            obj = std::make_shared<DisallowedSMSQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISALLOWED_MMS:
#ifdef MMS_EDM_ENABLE
            obj = std::make_shared<DisallowedMMSQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::GET_BUNDLE_INFO_LIST:
            obj = std::make_shared<InstalledBundleInfoListQuery>();
            return ERR_OK;
        case EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES:
#ifdef BLUETOOTH_EDM_ENABLE
            obj = std::make_shared<DisallowedBluetoothDevicesQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::ALLOWED_WIFI_LIST:
#ifdef WIFI_EDM_ENABLE
            obj = std::make_shared<AllowedWifiListQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISALLOWED_WIFI_LIST:
#ifdef WIFI_EDM_ENABLE
            obj = std::make_shared<DisallowedWifiListQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        default:
            break;
    }
    return GetPolicyQueryFifth(obj, code);
}

ErrCode PluginPolicyReader::GetPolicyQueryFifth(std::shared_ptr<IPolicyQuery> &obj, uint32_t code)
{
    switch (code) {
        case EdmInterfaceCode::DISALLOWED_MOBILE_DATA:
#ifdef MOBILE_DATA_ENABLE
            obj = std::make_shared<DisallowedMobileDataQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISABLE_SET_BIOMETRICS_AND_SCREENLOCK:
            obj = std::make_shared<DisableSetBiometricsAndScreenLockQuery>();
            return ERR_OK;
        case EdmInterfaceCode::SET_AUTO_UNLOCK_AFTER_REBOOT:
#ifdef FEATURE_PC_ONLY
            obj = std::make_shared<GetAutoUnlockAfterRebootQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        default:
            break;
    }
    return GetPolicyQueryEnd(obj, code);
}

ErrCode PluginPolicyReader::GetPolicyQueryEnd(std::shared_ptr<IPolicyQuery> &obj, uint32_t code)
{
    switch (code) {
        case EdmInterfaceCode::DISALLOW_MODIFY_APN:
#ifdef APN_EDM_ENABLE
            obj = std::make_shared<DisallowModifyAPNQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISALLOW_POWER_LONG_PRESS:
#ifdef POWER_MANAGER_EDM_ENABLE
            obj = std::make_shared<DisallowPowerLongPressQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISABLE_SAMBA_CLIENT:
#ifdef SAMBA_EDM_ENABLE
            obj = std::make_shared<DisableSambaClientQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISABLE_SAMBA_SERVER:
#ifdef SAMBA_EDM_ENABLE
            obj = std::make_shared<DisableSambaServerQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISALLOWED_NFC:
#ifdef NFC_EDM_ENABLE
            obj = std::make_shared<DisallowedNFCQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISALLOW_MODIFY_ETHERNET_IP:
#ifdef FEATURE_PC_ONLY
            obj = std::make_shared<DisallowModifyEthernetIpQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
        case EdmInterfaceCode::DISALLOW_VPN:
#ifdef NETMANAGER_EXT_EDM_ENABLE
            obj = std::make_shared<DisallowVPNQuery>();
            return ERR_OK;
#else
            return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
    }
    return ERR_CANNOT_FIND_QUERY_FAILED;
}
} // namespace EDM
} // namespace OHOS