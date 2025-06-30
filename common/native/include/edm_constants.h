/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef COMMON_NATIVE_INCLUDE_EDM_CONSTANTS_H
#define COMMON_NATIVE_INCLUDE_EDM_CONSTANTS_H

#include <iostream>

namespace OHOS {
namespace EDM {
namespace EdmConstants {
    constexpr int32_t DECIMAL = 10;
    constexpr uint32_t APPID_MAX_SIZE = 200;
    constexpr int32_t DEFAULT_USER_ID = 100;
    constexpr int32_t BLUETOOTH_SERVICE_UID = 1002;
    constexpr int32_t USERIAM_SERVICE_UID = 1088;
    constexpr int32_t USB_SERVICE_UID = 1018;
    constexpr int32_t USB_ERRCODE_INTERFACE_NO_INIT = 88080389;
    constexpr uint32_t ALLOWED_USB_DEVICES_MAX_SIZE = 1000;
    constexpr uint32_t WIFI_LIST_MAX_SIZE = 200;
    constexpr uint32_t WIFI_BSSID_LENGTH = 17;
    constexpr uint32_t WIFI_SSID_MAX_LENGTH = 32;
    constexpr int32_t STORAGE_USB_POLICY_READ_WRITE = 0;
    constexpr int32_t STORAGE_USB_POLICY_READ_ONLY = 1;
    constexpr int32_t STORAGE_USB_POLICY_DISABLED = 2;
    constexpr int32_t USB_INTERFACE_DESCRIPTOR = 0;
    constexpr int32_t USB_DEVICE_DESCRIPTOR = 1;
    constexpr uint32_t DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE = 200;
    constexpr uint32_t AUTO_START_APPS_MAX_SIZE = 10;
    constexpr uint32_t KEEP_ALIVE_APPS_MAX_SIZE = 5;
    constexpr uint32_t BLUETOOTH_LIST_MAX_SIZE = 1000;
    constexpr int32_t DISALLOW_LIST_FOR_ACCOUNT_MAX_SIZE = 1000;
    constexpr int32_t DEFAULT_LOOP_MAX_SIZE = 10000;
    constexpr uint32_t POLICIES_MAX_SIZE = 200;
    constexpr uint32_t AUTH_INFO_MAX_SIZE = 65535;

    constexpr size_t MAX_PARCEL_CAPACITY = 100 * 1024 * 1024; // 100M
    constexpr size_t MAX_PARCEL_CAPACITY_OF_ASHMEM = 1024 * 1024 * 1024; // max allow 1 GB resource size
    constexpr size_t MAX_IPC_RAWDATA_SIZE = 120 * 1024 * 1024; // max ipc size 120MB

    const char* const PERMISSION_TAG_VERSION_11 = "version_11";
    const char* const PERMISSION_TAG_VERSION_12 = "version_12";
    const char* const PERMISSION_TAG_SYSTEM_API = "system";
    const char* const PERMISSION_TAG_NORMAL = "normal";
    const char* const EDM_CONFIG_CHANGED_EVENT = "usual.event.EDM_CONFIG_CHANGED";

    const char* const DISALLOW_FOR_ACCOUNT_TYPE = "disallowForAccount";
    const char* const FINGERPRINT_AUTH_TYPE = "fingerprintAuth";

    // app-distribution-type
    constexpr const char* APP_DISTRIBUTION_TYPE_NONE = "none";

    constexpr const char* APP_PROVISION_TYPE_RELEASE = "release";

    namespace ApplicationManager {
        const char* const PARAM_EDM_KIOSK_ALLOW_NOTIFICATION_CENTER = "persist.edm.kiosk.allow_notification_center";
        const char* const PARAM_EDM_KIOSK_ALLOW_CONTROL_CENTER = "persist.edm.kiosk.allow_control_center";
    }

    namespace Browser {
        const char* const GET_MANAGED_BROWSER_VERSION = "version";
        const char* const GET_MANAGED_BROWSER_FILE_DATA = "fileData";
        const char* const GET_SELF_MANAGED_BROWSER_FILE_DATA = "selfFileData";
        const char* const BROWSER_WITHOUT_PERMISSION = "withoutPermission";
    }

    namespace DeviceInfo {
        const char* const DEVICE_NAME = "deviceName";
        const char* const DEVICE_SERIAL = "deviceSerial";
        const char* const SIM_INFO = "simInfo";
        const char* const SIM_SLOT_ID = "slotId";
        const char* const SIM_MEID = "MEID";
        const char* const SIM_IMSI = "IMSI";
        const char* const SIM_ICCID = "ICCID";
        const char* const SIM_IMEI = "IMEI";
        constexpr int32_t SIM_SLOT_ID_0 = 0;
        constexpr int32_t SIM_SLOT_ID_1 = 1;
    } // namespace DeviceInfo

    namespace PolicyCode {
        constexpr uint32_t DISALLOW_SCREEN_SHOT = 11;
        constexpr uint32_t DISALLOW_SCREEN_RECORD = 12;
        constexpr uint32_t DISABLE_DISK_RECOVERY_KEY = 17;
        constexpr uint32_t DISALLOW_NEAR_LINK = 18;
        constexpr uint32_t DISABLE_DEVELOPER_MODE = 20;
        constexpr uint32_t DISABLE_RESET_FACTORY = 21;
        constexpr uint32_t DISABLE_OTA = 23;
        constexpr uint32_t DISALLOWED_NFC = 24;
    }

    namespace KeepAlive {
        const char* const GET_MANAGE_KEEP_ALIVE_APPS_BUNDLE_NAME = "bundleName";
        const char* const GET_MANAGE_KEEP_ALIVE_APP_DISALLOW_MODIFY = "disallowModify";
    }

    namespace AutoStart {
        const char* const GET_MANAGE_AUTO_START_APPS_BUNDLE_INFO = "bundleInfo";
        const char* const GET_MANAGE_AUTO_START_APP_DISALLOW_MODIFY = "disallowModify";
    }

    namespace Restrictions {
        const char* const LABEL_DISALLOWED_POLICY_BLUETOOTH = "bluetooth";
        const char* const LABEL_DISALLOWED_POLICY_MODIFY_DATETIME = "modifyDateTime";
        const char* const LABEL_DISALLOWED_POLICY_PRINTER = "printer";
        const char* const LABEL_DISALLOWED_POLICY_HDC = "hdc";
        const char* const LABEL_DISALLOWED_POLICY_MIC = "microphone";
        const char* const LABEL_DISALLOWED_POLICY_FINGER_PRINT = "fingerprint";
        const char* const LABEL_DISALLOWED_POLICY_SCREENSHOT = "screenshot";
        const char* const LABEL_DISALLOWED_POLICY_SCREEN_RECORD = "screenRecord";
        const char* const LABEL_DISALLOWED_POLICY_USB = "usb";
        const char* const LABEL_DISALLOWED_POLICY_USB_STORAGE_DEVICE_WRITE = "usbStorageDeviceWrite";
        const char* const LABEL_DISALLOWED_POLICY_WIFI = "wifi";
        const char* const LABEL_DISALLOWED_POLICY_DEVELOPER_MODE = "developerMode";
        const char* const LABEL_DISALLOWED_POLICY_DISK_RECOVERY_KEY = "diskRecoveryKey";
        const char* const LABEL_DISALLOWED_POLICY_NEAR_LINK = "nearLink";
        const char* const LABEL_DISALLOWED_POLICY_TETHERING = "tethering";
        const char* const LABEL_DISALLOWED_POLICY_INACTIVE_USER_FREEZE = "inactiveUserFreeze";
        const char* const LABEL_DISALLOWED_POLICY_CAMERA = "camera";
        const char* const LABEL_DISALLOWED_POLICY_RESET_FACTORY = "resetFactory";
        const char* const LABEL_DISALLOWED_POLICY_MTP_CLIENT = "mtpClient";
        const char* const LABEL_DISALLOWED_POLICY_MTP_SERVER = "mtpServer";
        const char* const LABEL_DISALLOWED_POLICY_SAMBA_CLIENT = "sambaClient";
        const char* const LABEL_DISALLOWED_POLICY_SAMBA_SERVER = "sambaServer";
        const char* const LABEL_DISALLOWED_POLICY_REMOTE_DESK = "remoteDesk";
        const char* const LABEL_DISALLOWED_POLICY_REMOTE_DIAGNOSIS = "remoteDiagnosis";
        const char* const LABEL_DISALLOWED_POLICY_MAINTENANCE_MODE = "maintenanceMode";
        const char* const LABEL_DISALLOWED_POLICY_SMS = "sms";
        const char* const LABEL_DISALLOWED_POLICY_MMS = "mms";
        const char* const LABEL_DISALLOWED_POLICY_BACKUP_AND_RESTORE = "backupAndRestore";
        const char* const LABEL_DISALLOWED_POLICY_APN = "setApn";
        const char* const LABEL_DISALLOWED_POLICY_DISTRIBUTED_TRANSMISSION = "distributedTransmissionOutgoing";
        const char* const LABEL_DISALLOWED_POLICY_MOBILE_DATA = "mobileData";
        const char* const LABEL_DISALLOWED_POLICY_POWER_LONG_PRESS = "powerLongPress";
        const char* const LABEL_DISALLOWED_POLICY_NFC = "nfc";
        const char* const LABEL_DISALLOWED_POLICY_AIRPLANE_MODE = "airplaneMode";
        const char* const LABEL_DISALLOWED_POLICY_SET_BIOMETRICS_AND_SCREENLOCK = "setBiometricsAndScreenLock";
        const char* const LABEL_DISALLOWED_POLICY_ETHERNET_IP = "setEthernetIp";
        const char* const LABEL_DISALLOWED_POLICY_SET_DEVICE_NAME = "setDeviceName";
        const char* const LABEL_DISALLOWED_POLICY_SUDO = "sudo";
        const char* const LABEL_DISALLOWED_POLICY_NOTIFICATION = "notification";
        const char* const LABEL_DISALLOWED_POLICY_PRIVATE_SPACE = "privateSpace";
        const char* const LABEL_DISALLOWED_POLICY_TELEPHONY_CALL = "telephoneCall";
        const char* const LABEL_DISALLOWED_POLICY_VPN = "vpn";
        const char* const LABEL_DISALLOWED_POLICY_OTA = "otaUpdate";
    } // namespace Restrictions

    namespace SecurityManager {
        const char* const PATCH = "patch";
        const char* const ENCRYPTION = "encryption";
        const char* const ROOT = "root";
        const char* const SET_SINGLE_WATERMARK_TYPE = "single";
        const char* const SET_ALL_WATERMARK_TYPE = "all";
    } // namespace SecurityManager

    namespace DeviceSettings {
        const char* const SCREEN_OFF = "screenOff";
        const char* const POWER_POLICY = "powerPolicy";
        const char* const DATE_TIME = "dateTime";
    } // namespace DeviceSettings

    namespace DeviceControl {
        const char* const RESET_FACTORY = "resetFactory";
        const char* const REBOOT = "reboot";
        const char* const SHUT_DOWN = "shutDown";
        const char* const LOCK_SCREEN = "lockScreen";
    } // namespace DeviceControl

    namespace SetApn {
        constexpr uint32_t MAX_MAP_SIZE = 50;
        const std::string ADD_FLAG = "AddApn";
        const std::string UPDATE_FLAG = "UpdateApn";
        const std::string SET_PREFER_FLAG = "SetPreferApn";
        const std::string QUERY_ID_FLAG = "QueryApnIds";
        const std::string QUERY_INFO_FLAG = "QueryApn";
    }

    namespace MobileData {
        constexpr int32_t FORCE_OPEN = 2;
        const std::string DISALLOW_FLAG = "DisallowMobileData";
        const std::string FORCE_FLAG = "ForceMobileData";
    } // namespace MobileData

    namespace CallPolicy {
        constexpr uint32_t NUMBER_LIST_MAX_SIZE = 1000;
        const std::string OUTGOING = "outgoing";
        const std::string INCOMING = "incoming";
    }
} // namespace EdmConstants

namespace EdmPermission {
    // api 9
    const char* const PERMISSION_ENTERPRISE_SET_DATETIME = "ohos.permission.ENTERPRISE_SET_DATETIME";
    const char* const PERMISSION_ENTERPRISE_SUBSCRIBE_MANAGED_EVENT =
        "ohos.permission.ENTERPRISE_SUBSCRIBE_MANAGED_EVENT";
    const char* const PERMISSION_SET_ENTERPRISE_INFO = "ohos.permission.SET_ENTERPRISE_INFO";
    const char* const PERMISSION_MANAGE_ENTERPRISE_DEVICE_ADMIN = "ohos.permission.MANAGE_ENTERPRISE_DEVICE_ADMIN";
    // api 10
    const char* const PERMISSION_ENTERPRISE_SET_SCREEN_OFF_TIME = "ohos.permission.ENTERPRISE_SET_SCREENOFF_TIME";
    const char* const PERMISSION_ENTERPRISE_RESTRICT_POLICY = "ohos.permission.ENTERPRISE_RESTRICT_POLICY";
    const char* const PERMISSION_ENTERPRISE_GET_SETTINGS = "ohos.permission.ENTERPRISE_GET_SETTINGS";
    const char* const PERMISSION_ENTERPRISE_RESET_DEVICE = "ohos.permission.ENTERPRISE_RESET_DEVICE";
    const char* const PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY =
        "ohos.permission.ENTERPRISE_SET_BUNDLE_INSTALL_POLICY";
    const char* const PERMISSION_ENTERPRISE_GET_DEVICE_INFO = "ohos.permission.ENTERPRISE_GET_DEVICE_INFO";
    const char* const PERMISSION_ENTERPRISE_GET_NETWORK_INFO = "ohos.permission.ENTERPRISE_GET_NETWORK_INFO";
    const char* const PERMISSION_ENTERPRISE_SET_NETWORK = "ohos.permission.ENTERPRISE_SET_NETWORK";
    const char* const PERMISSION_ENTERPRISE_MANAGE_NETWORK = "ohos.permission.ENTERPRISE_MANAGE_NETWORK";
    const char* const PERMISSION_ENTERPRISE_INSTALL_BUNDLE = "ohos.permission.ENTERPRISE_INSTALL_BUNDLE";
    const char* const PERMISSION_ENTERPRISE_MANAGE_SET_APP_RUNNING_POLICY =
        "ohos.permission.ENTERPRISE_MANAGE_SET_APP_RUNNING_POLICY";
    const char* const PERMISSION_ENTERPRISE_SET_ACCOUNT_POLICY = "ohos.permission.ENTERPRISE_SET_ACCOUNT_POLICY";
    const char* const PERMISSION_ENTERPRISE_SET_WIFI = "ohos.permission.ENTERPRISE_SET_WIFI";
    const char* const PERMISSION_ENTERPRISE_MANAGE_USB = "ohos.permission.ENTERPRISE_MANAGE_USB";
    const char* const PERMISSION_ENTERPRISE_MANAGE_CERTIFICATE = "ohos.permission.ENTERPRISE_MANAGE_CERTIFICATE";
    const char* const PERMISSION_ENTERPRISE_SET_BROWSER_POLICY = "ohos.permission.ENTERPRISE_SET_BROWSER_POLICY";
    // api 11
    const char* const PERMISSION_ENTERPRISE_LOCK_DEVICE = "ohos.permission.ENTERPRISE_LOCK_DEVICE";
    const char* const PERMISSION_ENTERPRISE_REBOOT = "ohos.permission.ENTERPRISE_REBOOT";
    const char* const PERMISSION_ENTERPRISE_MANAGE_SETTINGS = "ohos.permission.ENTERPRISE_MANAGE_SETTINGS";
    const char* const PERMISSION_ENTERPRISE_MANAGE_SECURITY = "ohos.permission.ENTERPRISE_MANAGE_SECURITY";
    const char* const PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH = "ohos.permission.ENTERPRISE_MANAGE_BLUETOOTH";
    const char* const PERMISSION_ENTERPRISE_MANAGE_LOCATION = "ohos.permission.ENTERPRISE_MANAGE_LOCATION";
    const char* const PERMISSION_ENTERPRISE_MANAGE_WIFI = "ohos.permission.ENTERPRISE_MANAGE_WIFI";
    const char* const PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS = "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS";
    const char* const PERMISSION_ENTERPRISE_MANAGE_APPLICATION = "ohos.permission.ENTERPRISE_MANAGE_APPLICATION";
    const char* const PERMISSION_ENTERPRISE_MANAGE_SYSTEM = "ohos.permission.ENTERPRISE_MANAGE_SYSTEM";
    // api 12
    const char* const PERMISSION_ENTERPRISE_OPERATE_DEVICE = "ohos.permission.ENTERPRISE_OPERATE_DEVICE";
    // api 14
    const char* const PERMISSION_ENTERPRISE_MANAGE_DELEGATED_POLICY =
        "ohos.permission.ENTERPRISE_MANAGE_DELEGATED_POLICY";
    // api 15
    const char* const PERMISSION_PERSONAL_MANAGE_RESTRICTIONS = "ohos.permission.PERSONAL_MANAGE_RESTRICTIONS";
    // api 20
    const char* const PERMISSION_ENTERPRISE_SET_USER_RESTRICTION = "ohos.permission.ENTERPRISE_SET_USER_RESTRICTION";
    const char* const PERMISSION_ENTERPRISE_GET_ALL_BUNDLE_INFO = "ohos.permission.ENTERPRISE_GET_ALL_BUNDLE_INFO";
    const char* const PERMISSION_ENTERPRISE_MANAGE_APN = "ohos.permission.ENTERPRISE_MANAGE_APN";
    const char* const PERMISSION_ENTERPRISE_MANAGE_TELEPHONY = "ohos.permission.ENTERPRISE_MANAGE_TELEPHONY";
    const char* const PERMISSION_ENTERPRISE_SET_KIOSK = "ohos.permission.ENTERPRISE_SET_KIOSK";
} // namespace EdmPermission
namespace PolicyName {
    // open-source
    const char* const POLICY_ADD_OS_ACCOUNT = "add_os_account";
    const char* const POLICY_ALLOWED_BLUETOOTH_DEVICES = "allowed_bluetooth_devices";
    const char* const POLICY_ALLOWED_KIOSK_APPS = "allowed_kiosk_apps";
    const char* const POLICY_DISALLOWED_BLUETOOTH_DEVICES = "disallowed_bluetooth_devices";
    const char* const POLICY_ALLOWED_INSTALL_BUNDLES = "allowed_install_bundles";
    const char* const POLICY_ALLOWED_USB_DEVICES = "allowed_usb_devices";
    const char* const POLICY_CLIPBOARD_POLICY = "clipboard_policy";
    const char* const POLICY_DISABLED_BLUETOOTH = "disabled_bluetooth";
    const char* const POLICY_DISABLE_CAMERA = "disable_camera";
    const char* const POLICY_DISABLED_HDC = "disabled_hdc";
    const char* const POLICY_DISABLED_MAINTENANCE_MODE = "disabled_maintenance_mode";
    const char* const POLICY_DISABLE_MICROPHONE = "disable_microphone";
    const char* const POLICY_DISABLED_MTP_CLIENT = "disabled_mtp_client";
    const char* const POLICY_DISABLED_MTP_SERVER = "disabled_mtp_server";
    const char* const POLICY_DISABLED_PRIVATE_SPACE = "disabled_private_space";
    const char* const POLICY_DISABLED_SAMBA_CLIENT = "disabled_samba_client";
    const char* const POLICY_DISABLED_SAMBA_SERVER = "disabled_samba_server";
    const char* const POLICY_DISABLED_REMOTE_DESK = "disabled_remote_desk";
    const char* const POLICY_DISABLED_REMOTE_DIAGNOSIS = "disabled_remote_diagnosis";
    const char* const POLICY_DISABLED_SUDO = "disabled_sudo";
    const char* const POLICY_DISABLED_USER_MTP_CLIENT = "disabled_user_mtp_client";
    const char* const POLICY_DISABLED_PRINTER = "disabled_printer";
    const char* const POLICY_DISABLE_USB = "disable_usb";
    const char* const POLICY_DISABLED_NETWORK_INTERFACE = "disabled_network_interface";
    const char* const POLICY_DISALLOW_ADD_LOCAL_ACCOUNT = "disallow_add_local_account";
    const char* const POLICY_DISALLOW_ADD_OS_ACCOUNT_BY_USER = "disallow_add_os_account_by_user";
    const char* const POLICY_DISALLOW_MODIFY_DATETIME = "disallow_modify_datetime";
    const char* const POLICY_DISALLOWED_INSTALL_BUNDLES = "disallowed_install_bundles";
    const char* const POLICY_DISALLOW_RUNNING_BUNDLES = "disallow_running_bundles";
    const char* const POLICY_DISALLOWED_BLUETOOTH_PROTOCOLS = "disallowed_bluetooth_protocols";
    const char* const POLICY_DISALLOWED_NEARLINK_PROTOCOLS = "disallowed_nearlink_protocols";
    const char* const POLICY_DISALLOWED_TETHERING = "disallowed_tethering";
    const char* const POLICY_DISALLOWED_SMS = "disallowed_sms";
    const char* const POLICY_DISALLOWED_UNINSTALL_BUNDLES = "disallowed_uninstall_bundles";
    const char* const POLICY_DISALLOWED_USB_DEVICES = "disallowed_usb_devices";
    const char* const POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION = "disallowed_distributed_transmission";
    const char* const POLICY_DISALLOWED_USB_STORAGE_DEVICE_WRITE = "disallowed_usb_storage_device_write";
    const char* const POLICY_DOMAIN_FILTER_RULE = "domain_filter_rule";
    const char* const POLICY_FINGERPRINT_AUTH = "fingerprint_auth";
    const char* const POLICY_FIREWALL_RULE = "firewall_rule";
    const char* const POLICY_GET_ADMINPROVISION_INFO = "get_adminprovision_info";
    const char* const POLICY_GET_NETWORK_INTERFACES = "get_network_interfaces";
    const char* const POLICY_GET_BLUETOOTH_INFO = "get_bluetooth_info";
    const char* const POLICY_GET_DEVICE_INFO = "get_device_info";
    const char* const POLICY_GET_IP_ADDRESS = "get_ip_address";
    const char* const POLICY_GET_MAC = "get_mac";
    const char* const POLICY_GLOBAL_PROXY = "global_proxy";
    const char* const POLICY_INACTIVE_USER_FREEZE = "inactive_user_freeze";
    const char* const POLICY_INSTALL = "install";
    const char* const POLICY_IPTABLES_RULE = "iptables_rule";
    const char* const POLICY_IS_WIFI_ACTIVE = "is_wifi_active";
    const char* const POLICY_LOCATION_POLICY = "location_policy";
    const char* const POLICY_LOCK_SCREEN = "lock_screen";
    const char* const POLICY_MANAGE_AUTO_START_APPS = "manage_auto_start_apps";
    const char* const POLICY_MANAGE_KEEP_ALIVE_APPS = "manage_keep_alive_apps";
    const char* const POLICY_MANAGED_BROWSER_POLICY = "managed_browser_policy";
    const char* const POLICY_NOTIFY_UPGRADE_PACKAGES = "notify_upgrade_packages";
    const char* const POLICY_NTP_SERVER = "ntp_server";
    const char* const POLICY_OPERATE_DEVICE = "operate_device";
    const char* const POLICY_PASSWORD_POLICY = "password_policy";
    const char* const POLICY_POWER_POLICY = "power_policy";
    const char* const POLICY_REBOOT = "reboot";
    const char* const POLICY_RESET_FACTORY = "reset_factory";
    const char* const POLICY_SCREEN_OFF_TIME = "screen_off_time";
    const char* const POLICY_SET_BROWSER_POLICIES = "set_browser_policies";
    const char* const POLICY_SET_DATETIME = "set_datetime";
    const char* const POLICY_SET_DOMAIN_ACCOUNT_POLICY = "set_domain_account_policy";
    const char* const POLICY_SET_UPDATE_POLICY = "set_update_policy";
    const char* const POLICY_DISABLE_WIFI = "disable_wifi";
    const char* const POLICY_SET_WIFI_PROFILE = "set_wifi_profile";
    const char* const POLICY_ALLOWED_WIFI_LIST = "allowed_wifi_list";
    const char* const POLICY_DISALLOWED_WIFI_LIST = "disallowed_wifi_list";
    const char* const POLICY_ALLOWED_INSTALL_APP_TYPE = "allowed_install_app_type";
    const char* const POLICY_SHUTDOWN_DEVICE = "shutdown_device";
    const char* const POLICY_SNAPSHOT_SKIP = "snapshot_skip";
    const char* const POLICY_UNINSTALL = "uninstall";
    const char* const POLICY_USB_READ_ONLY = "usb_read_only";
    const char* const POLICY_INSTALL_CERTIFICATE = "install_certificate";
    const char* const POLICY_WATERMARK_IMAGE_POLICY = "watermark_image_policy";
    const char* const POLICY_DISALLOWED_MMS = "disallowed_mms";
    const char* const POLICY_DISABLE_BACKUP_AND_RESTORE = "disable_backup_and_restore";
    const char* const POLICY_DISALLOW_MODIFY_APN = "disallow_modify_apn";
    const char* const POLICY_INSTALLED_BUNDLE_INFO_LIST = "installed_bundle_info_list";
    const char* const POLICY_CLEAR_UP_APPLICATION_DATA = "clear_up_application_data";
    const char* const POLICY_SET_APN_INFO = "set_apn_info";
    const char* const POLICY_DISALLOW_SIM = "disallowed_sim";
    const char* const POLICY_DISALLOW_MOBILE_DATA = "disallow_mobile_data";
    const char* const POLICY_DISALLOW_POWER_LONG_PRESS = "disallow_power_long_press";
    const char* const POLICY_SET_KIOSK_FEATURE = "kiosk_feature";
    const char* const POLICY_DISALLOWED_AIRPLANE_MODE = "disallowed_airplane_mode";
    const char* const POLICY_SET_BIOMETRICS_AND_SCREENLOCK = "set_biometrics_and_screenLock";
    const char* const POLICY_SET_DEVICE_NAME = "set_device_name";
    const char* const POLICY_DISALLOW_MODIFY_ETHERNET_IP = "disallow_modify_ethernet_ip";
    const char* const POLICY_DISALLOW_VPN = "disallow_vpn";
    const char* const POLICY_SET_AUTO_UNLOCK_AFTER_REBOOT = "set_auto_unlock_after_reboot";
    const char* const POLICY_DISALLOWED_NOTIFICATION = "disallowed_notification";
    const char* const POLICY_SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED = "set_install_local_enterprise_app_enabled";
    const char* const POLICY_TELEPHONY_CALL_POLICY = "telephony_call_policy";
    const char* const POLICY_DISALLOWED_TELEPHONY_CALL = "disallowed_telephony_call";
    // closed-source
    const char* const POLICY_GET_DEVICE_ENCRYPTION_STATUS = "get_device_encryption_status";
    const char* const POLICY_GET_DISPLAY_VERSION = "get_display_version";
    const char* const POLICY_GET_SECURITY_PATCH_TAG = "get_security_patch_tag";
    const char* const POLICY_POLICY_SCREEN_SHOT = "policy_screen_shot";
    const char* const POLICY_POLICY_SCREEN_RECORD = "policy_screen_record";
    const char* const POLICY_ALLOW_ALL = "allow_all";
} // namespace PolicyName
} // namespace EDM
} // namespace OHOS

#endif // COMMON_NATIVE_INCLUDE_EDM_CONSTANTS_H
