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
    constexpr int32_t APPID_MAX_SIZE = 200;
    constexpr int32_t DEFAULT_USER_ID = 100;
    constexpr int32_t USB_ERRCODE_INTERFACE_NO_INIT = 88080389;
    constexpr uint32_t ALLOWED_USB_DEVICES_MAX_SIZE = 1000;
    constexpr int32_t STORAGE_USB_POLICY_READ_WRITE = 0;
    constexpr int32_t STORAGE_USB_POLICY_READ_ONLY = 1;
    constexpr int32_t STORAGE_USB_POLICY_DISABLED = 2;
    constexpr int32_t USB_INTERFACE_DESCRIPTOR = 0;
    constexpr int32_t USB_DEVICE_DESCRIPTOR = 1;
    constexpr uint32_t DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE = 200;
    constexpr int32_t AUTO_START_APPS_MAX_SIZE = 10;
    constexpr int32_t KEEP_ALIVE_APPS_MAX_SIZE = 5;
    constexpr int32_t BLUETOOTH_WHITELIST_MAX_SIZE = 1000;
    constexpr int32_t DISALLOW_LIST_FOR_ACCOUNT_MAX_SIZE = 1000;
    constexpr int32_t DEFAULT_LOOP_MAX_SIZE = 10000;
    constexpr uint32_t POLICIES_MAX_SIZE = 200;

    const char* const PERMISSION_TAG_VERSION_11 = "version_11";
    const char* const PERMISSION_TAG_VERSION_12 = "version_12";
    const char* const PERMISSION_TAG_SYSTEM_API = "system";
    const char* const PERMISSION_TAG_NORMAL = "normal";

    const char* const DISALLOW_FOR_ACCOUNT_TYPE = "disallowForAccount";
    const char* const FINGERPRINT_AUTH_TYPE = "fingerprintAuth";

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
        const char* const LABEL_DISALLOWED_POLICY_WIFI = "wifi";
        const char* const LABEL_DISALLOWED_POLICY_DEVELOPER_MODE = "developerMode";
        const char* const LABEL_DISALLOWED_POLICY_DISK_RECOVERY_KEY = "diskRecoveryKey";
        const char* const LABEL_DISALLOWED_POLICY_NEAR_LINK = "nearLink";
        const char* const LABEL_DISALLOWED_POLICY_TETHERING = "tethering";
        const char* const LABEL_DISALLOWED_POLICY_INACTIVE_USER_FREEZE = "inactiveUserFreeze";
        const char* const LABEL_DISALLOWED_POLICY_CAMERA = "camera";
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
} // namespace EdmConstants
} // namespace EDM
} // namespace OHOS

#endif // COMMON_NATIVE_INCLUDE_EDM_CONSTANTS_H
