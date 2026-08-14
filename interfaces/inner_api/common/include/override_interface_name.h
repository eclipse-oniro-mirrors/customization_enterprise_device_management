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

#ifndef INTERFACES_INNER_API_COMMON_INCLUDE_OVERRIDE_INTERFACE_NAME_H
#define INTERFACES_INNER_API_COMMON_INCLUDE_OVERRIDE_INTERFACE_NAME_H

#include <string>

namespace OHOS {
namespace EDM {
namespace OverrideInterfaceName {
    namespace AccountManager {
        const char* const SET_DOMAIN_ACCOUNT_POLICY = "setDomainAccountPolicy";
    } // namespace AccountManager

    namespace ApplicationManager {
        const char* const SET_ALLOWED_KIOSK_APPS = "setAllowedKioskApps";
    } // namespace ApplicationManager

    namespace Browser {
        const char* const SET_POLICY_SYNC = "setPolicySync";
    } // namespace Browser

    namespace DeviceSettings {
        const char* const SET_VALUE = "setValue";
        const char* const SET_HOME_WALLPAPER = "setHomeWallpaper";
        const char* const SET_UNLOCK_WALLPAPER = "setUnlockWallpaper";
        const char* const SET_SWITCH_STATUS = "setSwitchStatus";
    } // namespace DeviceSettings

    namespace NetworkManager {
        const char* const ADD_FIREWALL_RULE = "addFirewallRule";
        const char* const REMOVE_FIREWALL_RULE = "removeFirewallRule";
        const char* const ADD_DOMAIN_FILTER_RULE = "addDomainFilterRule";
        const char* const REMOVE_DOMAIN_FILTER_RULE = "removeDomainFilterRule";
        const char* const SET_GLOBAL_PROXY_SYNC = "setGlobalProxySync";
        const char* const SET_GLOBAL_PROXY_FOR_ACCOUNT = "setGlobalProxyForAccount";
        const char* const ADD_APN = "addApn";
        const char* const DELETE_APN = "deleteApn";
        const char* const UPDATE_APN = "updateApn";
        const char* const SET_PREFERRED_APN = "setPreferredApn";
        const char* const SET_ETHERNET_CONFIG = "setEthernetConfig";
    } // namespace NetworkManager

    namespace SecurityManager {
        const char* const SET_PASSWORD_POLICY = "setPasswordPolicy";
        const char* const SET_DEVICE_SECURITY_LEVEL_POLICY = "setDeviceSecurityLevelPolicy";
        const char* const UNINSTALL_ENTERPRISE_RE_SIGNATURE_CERTIFICATE = "uninstallEnterpriseReSignatureCertificate";
        const char* const INSTALL_ENTERPRISE_RE_SIGNATURE_CERTIFICATE = "installEnterpriseReSignatureCertificate";
    } // namespace SecurityManager

    namespace SystemManager {
        const char* const SET_NTP_SERVER = "setNTPServer";
        const char* const SET_ACTIVATION_LOCK_DISABLED = "setActivationLockDisabled";
    } // namespace SystemManager

    namespace WifiManager {
        const char* const SET_WIFI_PROFILE_SYNC = "setWifiProfileSync";
    } // namespace WifiManager
} // namespace OverrideInterfaceName
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_COMMON_INCLUDE_OVERRIDE_INTERFACE_NAME_H
