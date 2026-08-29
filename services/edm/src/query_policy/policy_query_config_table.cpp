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

#include <algorithm>

#include "policy_query_config_table.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin.h"

namespace OHOS {
namespace EDM {

namespace {
static const PolicyQueryConfigEntry CONFIG_TABLE[] = {
    {EdmInterfaceCode::GET_DISPLAY_VERSION, {PolicyName::POLICY_GET_DISPLAY_VERSION, PolicyDataType::CUSTOM,
        PermissionConfig::SpecificPermission(EdmPermission::PERMISSION_ENTERPRISE_GET_DEVICE_INFO), true,
        IPlugin::ApiType::SYSTEM, true}},
    {EdmInterfaceCode::DISALLOW_ADD_LOCAL_ACCOUNT, {PolicyName::POLICY_DISALLOW_ADD_LOCAL_ACCOUNT,
        PolicyDataType::BOOL, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_SET_ACCOUNT_POLICY), true, IPlugin::ApiType::PUBLIC,
#ifdef OS_ACCOUNT_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::ALLOWED_INSTALL_BUNDLES, {PolicyName::POLICY_ALLOWED_INSTALL_BUNDLES,
        PolicyDataType::ARRAY_STRING, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOW_MODIFY_DATETIME, {PolicyName::POLICY_DISALLOW_MODIFY_DATETIME,
        PolicyDataType::BOOL, PermissionConfig::TagPermission(
        EdmPermission::PERMISSION_ENTERPRISE_SET_DATETIME,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOW_RUNNING_BUNDLES, {PolicyName::POLICY_DISALLOW_RUNNING_BUNDLES,
        PolicyDataType::ARRAY_STRING, PermissionConfig::TagPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SET_APP_RUNNING_POLICY,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION), true, IPlugin::ApiType::PUBLIC,
#ifdef ABILITY_RUNTIME_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOWED_INSTALL_BUNDLES, {PolicyName::POLICY_DISALLOWED_INSTALL_BUNDLES,
        PolicyDataType::ARRAY_STRING, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOWED_UNINSTALL_BUNDLES, {PolicyName::POLICY_DISALLOWED_UNINSTALL_BUNDLES,
        PolicyDataType::ARRAY_STRING, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISABLED_PRINTER, {PolicyName::POLICY_DISABLED_PRINTER, PolicyDataType::BOOL,
        PermissionConfig::TagPermission(EdmPermission::PERMISSION_ENTERPRISE_RESTRICT_POLICY,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS), true, IPlugin::ApiType::PUBLIC,
#ifdef AUDIO_FRAMEWORK_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISABLED_HDC, {PolicyName::POLICY_DISABLED_HDC, PolicyDataType::BOOL,
        PermissionConfig::TagPermission(EdmPermission::PERMISSION_ENTERPRISE_RESTRICT_POLICY,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS), true, IPlugin::ApiType::PUBLIC,
#ifdef AUDIO_FRAMEWORK_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::SET_BROWSER_POLICIES, {PolicyName::POLICY_SET_BROWSER_POLICIES,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(""), true, IPlugin::ApiType::PUBLIC,
        true
    }},
    {EdmInterfaceCode::USB_READ_ONLY, {PolicyName::POLICY_USB_READ_ONLY, PolicyDataType::INT,
        PermissionConfig::TagPermission(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS), true, IPlugin::ApiType::PUBLIC,
#ifdef USB_DISK_MANAGER_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::NTP_SERVER, {PolicyName::POLICY_NTP_SERVER, PolicyDataType::CUSTOM,
        PermissionConfig::SpecificPermission(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::GET_SECURITY_PATCH_TAG, {PolicyName::POLICY_GET_SECURITY_PATCH_TAG,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::GET_DEVICE_ENCRYPTION_STATUS, {PolicyName::POLICY_GET_DEVICE_ENCRYPTION_STATUS,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::LOCATION_POLICY, {PolicyName::POLICY_LOCATION_POLICY, PolicyDataType::CUSTOM,
        PermissionConfig::SpecificPermission(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_LOCATION), true,
        IPlugin::ApiType::PUBLIC,
#ifdef LOCATION_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISABLE_USB, {PolicyName::POLICY_DISABLE_USB, PolicyDataType::BOOL,
        PermissionConfig::TagPermission(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS), true, IPlugin::ApiType::PUBLIC,
#ifdef USB_SERVICE_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::ALLOWED_USB_DEVICES, {PolicyName::POLICY_ALLOWED_USB_DEVICES,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB), true, IPlugin::ApiType::PUBLIC,
#ifdef USB_SERVICE_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISABLE_WIFI, {PolicyName::POLICY_DISABLE_WIFI, PolicyDataType::BOOL,
        PermissionConfig::TagPermission(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS), true, IPlugin::ApiType::PUBLIC,
#ifdef WIFI_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISABLE_MICROPHONE, {PolicyName::POLICY_DISABLE_MICROPHONE, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(true), true, IPlugin::ApiType::PUBLIC,
#ifdef AUDIO_FRAMEWORK_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISABLE_BLUETOOTH, {PolicyName::POLICY_DISABLED_BLUETOOTH, PolicyDataType::BOOL,
        PermissionConfig::TagPermission(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS), true, IPlugin::ApiType::PUBLIC,
#ifdef BLUETOOTH_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::FINGERPRINT_AUTH, {PolicyName::POLICY_FINGERPRINT_AUTH, PolicyDataType::CUSTOM,
        PermissionConfig::RestrictionPermission(), true, IPlugin::ApiType::PUBLIC,
#ifdef USERIAM_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::PASSWORD_POLICY, {PolicyName::POLICY_PASSWORD_POLICY, PolicyDataType::CUSTOM,
        PermissionConfig::TagPermission("", EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY), true,
        IPlugin::ApiType::PUBLIC,
#ifdef USERIAM_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES, {PolicyName::POLICY_ALLOWED_BLUETOOTH_DEVICES,
        PolicyDataType::ARRAY_STRING, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH), true, IPlugin::ApiType::PUBLIC,
#ifdef BLUETOOTH_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::CLIPBOARD_POLICY, {PolicyName::POLICY_CLIPBOARD_POLICY, PolicyDataType::CUSTOM,
        PermissionConfig::RestrictionPermission(true), true, IPlugin::ApiType::PUBLIC,
#ifdef PASTEBOARD_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOWED_TETHERING, {PolicyName::POLICY_DISALLOWED_TETHERING,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(true), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::INACTIVE_USER_FREEZE, {PolicyName::POLICY_INACTIVE_USER_FREEZE,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::SNAPSHOT_SKIP, {PolicyName::POLICY_SNAPSHOT_SKIP, PolicyDataType::ARRAY_STRING,
        PermissionConfig::RestrictionPermission(), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::WATERMARK_IMAGE, {PolicyName::POLICY_WATERMARK_IMAGE_POLICY,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISABLE_CAMERA, {PolicyName::POLICY_DISABLE_CAMERA, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(true), true, IPlugin::ApiType::PUBLIC,
#ifdef CAMERA_FRAMEWORK_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISABLE_MTP_CLIENT, {PolicyName::POLICY_DISABLED_MTP_CLIENT, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISABLE_MTP_SERVER, {PolicyName::POLICY_DISABLED_MTP_SERVER, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(true), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISABLE_MAINTENANCE_MODE, {PolicyName::POLICY_DISABLED_MAINTENANCE_MODE,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::ALLOWED_WIFI_LIST, {PolicyName::POLICY_ALLOWED_WIFI_LIST, PolicyDataType::CUSTOM,
        PermissionConfig::SpecificPermission(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI), true,
        IPlugin::ApiType::PUBLIC,
#ifdef WIFI_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOWED_WIFI_LIST, {PolicyName::POLICY_DISALLOWED_WIFI_LIST,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI), true, IPlugin::ApiType::PUBLIC,
#ifdef WIFI_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOWED_SMS, {PolicyName::POLICY_DISALLOWED_SMS, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(), true, IPlugin::ApiType::PUBLIC,
#ifdef SMS_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOWED_MMS, {PolicyName::POLICY_DISALLOWED_MMS, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(), true, IPlugin::ApiType::PUBLIC,
#ifdef MMS_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::GET_BUNDLE_INFO_LIST, {PolicyName::POLICY_INSTALLED_BUNDLE_INFO_LIST,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_GET_ALL_BUNDLE_INFO), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISABLE_BACKUP_AND_RESTORE, {PolicyName::POLICY_DISABLE_BACKUP_AND_RESTORE,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC,
#ifdef BACKUP_AND_RESTORE_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES, {PolicyName::POLICY_DISALLOWED_BLUETOOTH_DEVICES,
        PolicyDataType::ARRAY_STRING, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH), true, IPlugin::ApiType::PUBLIC,
#ifdef BLUETOOTH_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOW_MODIFY_APN, {PolicyName::POLICY_DISALLOW_MODIFY_APN,
        PolicyDataType::BOOL, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION), true, IPlugin::ApiType::PUBLIC,
#ifdef APN_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISABLE_USER_MTP_CLIENT, {PolicyName::POLICY_DISABLED_USER_MTP_CLIENT,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOWED_MOBILE_DATA, {PolicyName::POLICY_DISALLOW_MOBILE_DATA,
        PolicyDataType::BOOL, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK), true, IPlugin::ApiType::PUBLIC,
#ifdef MOBILE_DATA_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOW_MODIFY_ETHERNET_IP, {PolicyName::POLICY_DISALLOW_MODIFY_ETHERNET_IP,
        PolicyDataType::BOOL, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION), true, IPlugin::ApiType::PUBLIC,
#ifdef FEATURE_PC_ONLY
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISABLE_SET_BIOMETRICS_AND_SCREENLOCK, {PolicyName::POLICY_SET_BIOMETRICS_AND_SCREENLOCK,
        PolicyDataType::BOOL, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISABLE_SET_DEVICE_NAME, {PolicyName::POLICY_SET_DEVICE_NAME, PolicyDataType::BOOL,
        PermissionConfig::SpecificPermission(EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION),
        true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISABLE_SAMBA_CLIENT, {PolicyName::POLICY_DISABLED_SAMBA_CLIENT,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC,
#ifdef SAMBA_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISABLE_SAMBA_SERVER, {PolicyName::POLICY_DISABLED_SAMBA_SERVER,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC,
#ifdef SAMBA_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOW_POWER_LONG_PRESS, {PolicyName::POLICY_DISALLOW_POWER_LONG_PRESS,
        PolicyDataType::BOOL, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION), true, IPlugin::ApiType::PUBLIC,
#ifdef POWER_MANAGER_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::IS_APP_KIOSK_ALLOWED, {PolicyName::POLICY_ALLOWED_KIOSK_APPS,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(""), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOWED_AIRPLANE_MODE, {PolicyName::POLICY_DISALLOWED_AIRPLANE_MODE,
        PolicyDataType::BOOL, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK), true, IPlugin::ApiType::PUBLIC,
#ifdef NET_MANAGER_BASE_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE, {PolicyName::POLICY_ALLOWED_INSTALL_APP_TYPE,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOW_VPN, {PolicyName::POLICY_DISALLOW_VPN, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(), true, IPlugin::ApiType::PUBLIC,
#ifdef NETMANAGER_EXT_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::SET_AUTO_UNLOCK_AFTER_REBOOT, {PolicyName::POLICY_SET_AUTO_UNLOCK_AFTER_REBOOT,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM), true, IPlugin::ApiType::PUBLIC,
#ifdef FEATURE_PC_ONLY
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE, {PolicyName::POLICY_DISALLOWED_USB_STORAGE_DEVICE_WRITE,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC,
#ifdef FEATURE_PC_ONLY
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION, {PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOWED_SUDO, {PolicyName::POLICY_DISABLED_SUDO, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(), true, IPlugin::ApiType::PUBLIC,
#ifdef SUDO_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED, {PolicyName::POLICY_SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM), true, IPlugin::ApiType::PUBLIC,
#ifdef FEATURE_PC_ONLY
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOWED_NOTIFICATION, {PolicyName::POLICY_DISALLOWED_NOTIFICATION,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC,
#ifdef NOTIFICATION_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::TELEPHONY_CALL_POLICY, {PolicyName::POLICY_TELEPHONY_CALL_POLICY,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY), true, IPlugin::ApiType::PUBLIC,
#ifdef TELEPHONY_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOWED_TELEPHONY_CALL, {PolicyName::POLICY_DISALLOWED_TELEPHONY_CALL,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC,
#ifdef TELEPHONY_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISABLE_PRIVATE_SPACE, {PolicyName::POLICY_DISABLED_PRIVATE_SPACE,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC,
#ifdef PRIVATE_SPACE_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOWED_EXPORT_RECOVERY_KEY, {PolicyName::POLICY_DISALLOWED_EXPORT_RECOVERY_KEY,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC,
#ifdef FEATURE_PC_ONLY
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISABLED_PRINT, {PolicyName::POLICY_DISABLED_PRINT, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(), true, IPlugin::ApiType::PUBLIC,
#ifdef OS_ACCOUNT_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::PERMISSION_MANAGED_STATE, {PolicyName::POLICY_PERMISSION_MANAGED_STATE_POLICY,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USER_GRANT_PERMISSION), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISABLED_APP_CLONE, {PolicyName::POLICY_DISABLED_APP_CLONE, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOWED_RANDOM_MAC_ADDRESS, {PolicyName::POLICY_DISALLOWED_RANDOM_MAC_ADDRESS,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC,
#ifdef WIFI_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOWED_EXTERNAL_STORAGE_CARD, {PolicyName::POLICY_DISALLOWED_EXTERNAL_STORAGE_CARD,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC,
#ifdef EXTERNAL_DISK_MANAGER_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::ALLOW_RUNNING_BUNDLES, {PolicyName::POLICY_ALLOW_RUNNING_BUNDLES,
        PolicyDataType::ARRAY_STRING, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION), true, IPlugin::ApiType::PUBLIC,
#ifdef ABILITY_RUNTIME_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOW_UNMUTE_DEVICE, {PolicyName::POLICY_DISALLOW_UNMUTE_DEVICE,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISABLED_HDC_REMOTE, {PolicyName::POLICY_DISABLED_HDC_REMOTE,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC,
#ifdef FEATURE_PC_ONLY
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISABLE_RUNNING_BINARY_APP, {PolicyName::POLICY_DISABLE_RUNNING_BINARY_APP,
        PolicyDataType::INT, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY), true, IPlugin::ApiType::PUBLIC,
#ifdef FEATURE_PC_ONLY
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOW_VIRTUAL_SERVICE, {PolicyName::POLICY_DISALLOW_VIRTUAL_SERVICE,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOWED_FILEBOOST_OPEN, {PolicyName::POLICY_DISALLOWED_OPEN_FILE_BOOST,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC,
#ifdef FEATURE_PC_ONLY
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOW_MODIFY_WALLPAPER, {PolicyName::POLICY_DISALLOW_MODIFY_WALLPAPER,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC,
#ifdef OS_ACCOUNT_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::DISALLOW_USB_SERIAL, {PolicyName::POLICY_DISALLOW_USB_SERIAL,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT, {PolicyName::POLICY_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM), true, IPlugin::ApiType::PUBLIC,
#ifdef FEATURE_PC_ONLY
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::ALLOWED_NOTIFICATION_BUNDLES, {PolicyName::POLICY_ALLOWED_NOTIFICATION_BUNDLES,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOWED_P2P, {PolicyName::POLICY_DISALLOWED_P2P, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(true), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOWED_MULTI_WINDOW, {PolicyName::POLICY_DISALLOWED_MULTI_WINDOW,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC,
#ifdef MULTI_WINDOW_EDM_ENABLE
        true
#else
        false
#endif
    }},
    {EdmInterfaceCode::GET_BUNDLE_STORAGE_STATS, {PolicyName::POLICY_BUNDLE_STORAGE_STATS,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_GET_ALL_BUNDLE_INFO), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::QUERY_BUNDLE_STATS_INFOS, {PolicyName::POLICY_QUERY_BUNDLE_STATS_INFOS,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOWED_UINPUT, {PolicyName::POLICY_DISALLOW_UINPUT, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOW_CORE_DUMP, {PolicyName::POLICY_DISALLOW_CORE_DUMP, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL, {PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOWED_DEVICE_SUDO, {PolicyName::POLICY_DISALLOWED_DEVICE_SUDO,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::ALLOWED_COLLABORATION_SERVICE_BUNDLES, {PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES,
        PolicyDataType::ARRAY_STRING, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOW_RS232, {PolicyName::POLICY_DISALLOW_RS232, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOWED_TRAFFIC_REDIRECTION, {PolicyName::POLICY_DISALLOWED_TRAFFIC_REDIRECTION,
        PolicyDataType::BOOL, PermissionConfig::RestrictionPermission(), true,
        IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOWED_PERMISSION, {PolicyName::POLICY_DISALLOWED_PERMISSION,
        PolicyDataType::ARRAY_STRING, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::ALLOWED_PERMISSION_BUNDLE, {PolicyName::POLICY_ALLOWED_PERMISSION_BUNDLE,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DEVICE_SECURITY_LEVEL_POLICY, {PolicyName::POLICY_DEVICE_SECURITY_LEVEL_POLICY,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::DISALLOW_X_KEY, {PolicyName::POLICY_DISALLOW_X_KEY, PolicyDataType::BOOL,
        PermissionConfig::RestrictionPermission(), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_DEVICE,
        {PolicyName::POLICY_ALLOWED_PRINTER_IP_ADDRESSES_FOR_DEVICE,
        PolicyDataType::ARRAY_STRING, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM), true, IPlugin::ApiType::PUBLIC, true}},
    {EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_ACCOUNT,
        {PolicyName::POLICY_ALLOWED_PRINTER_IP_ADDRESSES_FOR_ACCOUNT,
        PolicyDataType::ARRAY_STRING, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM), true, IPlugin::ApiType::PUBLIC, true}},
    {static_cast<uint32_t>(EdmInterfaceCode::POLICY_CODE_END +
        EdmConstants::PolicyCode::HIDE_LAUNCHER_ICON), {PolicyName::POLICY_HIDE_LAUNCHER_ICON,
        PolicyDataType::CUSTOM, PermissionConfig::SpecificPermission(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION), true, IPlugin::ApiType::PUBLIC,
#ifdef FEATURE_PC_ONLY
        false
#else
        true
#endif
    }},
};

constexpr size_t CONFIG_TABLE_SIZE = sizeof(CONFIG_TABLE) / sizeof(CONFIG_TABLE[0]);
}

const PolicyQueryConfigEntry* PolicyQueryConfigTable::FindConfig(uint32_t code)
{
    auto it = std::lower_bound(CONFIG_TABLE, CONFIG_TABLE + CONFIG_TABLE_SIZE, code,
        [](const PolicyQueryConfigEntry &entry, uint32_t value) {
            return entry.code < value;
        });
    if (it != CONFIG_TABLE + CONFIG_TABLE_SIZE && it->code == code) {
        return it;
    }
    return nullptr;
}

const PolicyQueryConfigEntry* PolicyQueryConfigTable::GetAllEntries()
{
    return CONFIG_TABLE;
}

size_t PolicyQueryConfigTable::GetConfigCount()
{
    return CONFIG_TABLE_SIZE;
}

} // namespace EDM
} // namespace OHOS
