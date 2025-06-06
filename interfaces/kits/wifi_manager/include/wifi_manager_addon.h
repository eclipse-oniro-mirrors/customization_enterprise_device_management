/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_WIFI_MANAGER_INCLUDE_WIFI_MANAGER_ADDON_H
#define INTERFACES_KITS_WIFI_MANAGER_INCLUDE_WIFI_MANAGER_ADDON_H

#include "napi_edm_error.h"
#include "napi_edm_common.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi/native_api.h"
#include "want.h"
#include "wifi_id.h"
#include "wifi_manager_proxy.h"

#ifdef WIFI_EDM_ENABLE
#include "wifi_msg.h"
#include "wifi_password.h"
#endif

namespace OHOS {
namespace EDM {
struct AsyncIsWifiActiveCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
};

#ifdef WIFI_EDM_ENABLE
struct AsyncSetWifiProfileCallbackInfo : AsyncCallbackInfo {
    OHOS::AppExecFwk::ElementName elementName;
    OHOS::Wifi::WifiDeviceConfig wifiDeviceConfig;
    WifiPassword pwd;
};
#endif

enum class IpType {
    STATIC = 0,
    DHCP,
    UNKNOWN,
};

enum class SecurityType {
    // Invalid security type.
    SEC_TYPE_INVALID = 0,
    // Open.
    SEC_TYPE_OPEN = 1,
    // Wired Equivalent Privacy (WEP).
    SEC_TYPE_WEP = 2,
    // Pre-shared key (PSK).
    SEC_TYPE_PSK = 3,
    // Simultaneous Authentication of Equals (SAE).
    SEC_TYPE_SAE = 4,
    // EAP authentication.
    SEC_TYPE_EAP = 5,
    // SUITE_B_192 192 bit level.
    SEC_TYPE_EAP_SUITE_B = 6,
    // Opportunistic Wireless Encryption.
    SEC_TYPE_OWE = 7,
    // WAPI certificate to be specified.
    SEC_TYPE_WAPI_CERT = 8,
    // WAPI pre-shared key to be specified.
    SEC_TYPE_WAPI_PSK = 9,
};

enum class EapMethod {
    EAP_NONE = 0,
    EAP_PEAP = 1,
    EAP_TLS = 2,
    EAP_TTLS = 3,
    EAP_PWD = 4,
    EAP_SIM = 5,
    EAP_AKA = 6,
    EAP_AKA_PRIME = 7,
    EAP_UNAUTH_TLS = 8,
};

class WifiManagerAddon {
public:
    WifiManagerAddon() = default;
    ~WifiManagerAddon() = default;

    static napi_value Init(napi_env env, napi_value exports);
private:
#ifdef WIFI_EDM_ENABLE
    static bool JsObjToDeviceConfig(napi_env env, napi_value object, Wifi::WifiDeviceConfig &config,
        WifiPassword &pwd);
    static bool ConvertEncryptionMode(int32_t securityType, Wifi::WifiDeviceConfig &config, WifiPassword &pwd);
    static bool ProcessIpType(int32_t ipType, napi_env env, napi_value object, Wifi::WifiIpConfig &ipConfig);
    static bool ConfigStaticIp(napi_env env, napi_value object, Wifi::WifiIpConfig &ipConfig);
    static bool ProcessEapConfig(napi_env env, napi_value object,
        Wifi::WifiEapConfig &eapConfig, WifiPassword &pwd);
    static bool ProcessEapPeapConfig(napi_env env, napi_value object,
        Wifi::WifiEapConfig &eapConfig, WifiPassword &pwd);
    static bool ProcessEapTlsConfig(napi_env env, napi_value object, Wifi::WifiEapConfig &eapConfig);
#endif
    static napi_value IsWifiActive(napi_env env, napi_callback_info info);
    static napi_value IsWifiActiveHandler(napi_env env, napi_callback_info info, napi_async_execute_callback execute);
    static napi_value SetWifiProfile(napi_env env, napi_callback_info info);
    static napi_value SetWifiProfileHandler(napi_env env, napi_callback_info info, napi_async_execute_callback execute);
    static void NativeIsWifiActive(napi_env env, void *data);
    static void NativeSetWifiProfile(napi_env env, void *data);
    static void CreateWifiSecurityTypeObject(napi_env env, napi_value value);
    static void CreateIpTypeObject(napi_env env, napi_value value);
    static void CreateEapMethodObject(napi_env env, napi_value value);
    static void CreatePhase2MethodObject(napi_env env, napi_value value);
    static napi_value SetWifiDisabled(napi_env env, napi_callback_info info);
    static napi_value IsWifiDisabled(napi_env env, napi_callback_info info);
    static napi_value IsWifiActiveSync(napi_env env, napi_callback_info info);
    static napi_value SetWifiProfileSync(napi_env env, napi_callback_info info);
    static napi_value AddAllowedWifiList(napi_env env, napi_callback_info info);
    static napi_value GetAllowedWifiList(napi_env env, napi_callback_info info);
    static napi_value RemoveAllowedWifiList(napi_env env, napi_callback_info info);
    static napi_value AddOrRemoveAllowedWifiList(napi_env env, napi_callback_info info, bool isAdd);
    static bool ParseWifiInfoArray(napi_env env, std::vector<WifiId> &wifiIds, napi_value object, bool isAllowed);
    static bool GetWifiIdFromNAPI(napi_env env, napi_value value, WifiId &wifiId, bool isAllowed);
    static napi_value WifiIdToJsObj(napi_env env, const WifiId &wifiId);
    static napi_value AddDisallowedWifiList(napi_env env, napi_callback_info info);
    static napi_value GetDisallowedWifiList(napi_env env, napi_callback_info info);
    static napi_value RemoveDisallowedWifiList(napi_env env, napi_callback_info info);
    static napi_value AddOrRemoveDisallowedWifiList(napi_env env, napi_callback_info info, bool isAdd);
    static napi_value GetWifiList(napi_env env, napi_callback_info info, EdmInterfaceCode policyCode);
    static napi_value TurnOnWifi(napi_env env, napi_callback_info info);
    static napi_value TurnOffWifi(napi_env env, napi_callback_info info);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_WIFI_MANAGER_INCLUDE_WIFI_MANAGER_ADDON_H
