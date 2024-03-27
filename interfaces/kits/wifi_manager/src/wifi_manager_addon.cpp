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
#include "wifi_manager_addon.h"
#include "edm_log.h"
#include "message_parcel_utils.h"
#include "securec.h"

using namespace OHOS::EDM;

void WifiManagerAddon::CreateWifiSecurityTypeObject(napi_env env, napi_value value)
{
    napi_value nInvalid;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(SecurityType::SEC_TYPE_INVALID), &nInvalid));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WIFI_SEC_TYPE_INVALID", nInvalid));
    napi_value nOpen;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(SecurityType::SEC_TYPE_OPEN), &nOpen));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WIFI_SEC_TYPE_OPEN", nOpen));
    napi_value nWep;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(SecurityType::SEC_TYPE_WEP), &nWep));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WIFI_SEC_TYPE_WEP", nWep));
    napi_value nPsk;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(SecurityType::SEC_TYPE_PSK), &nPsk));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WIFI_SEC_TYPE_PSK", nPsk));
    napi_value nSae;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(SecurityType::SEC_TYPE_SAE), &nSae));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WIFI_SEC_TYPE_SAE", nSae));
    napi_value nEap;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(SecurityType::SEC_TYPE_EAP), &nEap));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WIFI_SEC_TYPE_EAP", nEap));
    napi_value nEapSuiteB;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(SecurityType::SEC_TYPE_EAP_SUITE_B), &nEapSuiteB));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WIFI_SEC_TYPE_EAP_SUITE_B", nEapSuiteB));
    napi_value nOwe;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(SecurityType::SEC_TYPE_OWE), &nOwe));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WIFI_SEC_TYPE_OWE", nOwe));
    napi_value nWapiCert;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(SecurityType::SEC_TYPE_WAPI_CERT), &nWapiCert));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WIFI_SEC_TYPE_WAPI_CERT", nWapiCert));
    napi_value nWapiPsk;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(SecurityType::SEC_TYPE_WAPI_PSK), &nWapiPsk));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "WIFI_SEC_TYPE_WAPI_PSK", nWapiPsk));
}

void WifiManagerAddon::CreateIpTypeObject(napi_env env, napi_value value)
{
    napi_value nStatic;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(IpType::STATIC), &nStatic));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "STATIC", nStatic));
    napi_value nDhcp;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(IpType::DHCP), &nDhcp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DHCP", nDhcp));
    napi_value nUnknown;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(IpType::UNKNOWN), &nUnknown));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UNKNOWN", nUnknown));
}

void WifiManagerAddon::CreateEapMethodObject(napi_env env, napi_value value)
{
    napi_value nNone;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(EapMethod::EAP_NONE), &nNone));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "EAP_NONE", nNone));
    napi_value nPeap;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(EapMethod::EAP_PEAP), &nPeap));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "EAP_PEAP", nPeap));
    napi_value nTls;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(EapMethod::EAP_TLS), &nTls));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "EAP_TLS", nTls));
    napi_value nTtls;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(EapMethod::EAP_TTLS), &nTtls));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "EAP_TTLS", nTtls));
    napi_value nPwd;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(EapMethod::EAP_PWD), &nPwd));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "EAP_PWD", nPwd));
    napi_value nSim;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(EapMethod::EAP_SIM), &nSim));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "EAP_SIM", nSim));
    napi_value nAka;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(EapMethod::EAP_AKA), &nAka));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "EAP_AKA", nAka));
    napi_value nAkaPrime;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(EapMethod::EAP_AKA_PRIME), &nAkaPrime));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "EAP_AKA_PRIME", nAkaPrime));
    napi_value nUnauthTls;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(EapMethod::EAP_UNAUTH_TLS), &nUnauthTls));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "EAP_UNAUTH_TLS", nUnauthTls));
}

void WifiManagerAddon::CreatePhase2MethodObject(napi_env env, napi_value value)
{
#ifdef WIFI_EDM_ENABLE
    napi_value nNone;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(Wifi::Phase2Method::NONE), &nNone));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PHASE2_NONE", nNone));
    napi_value nPap;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(Wifi::Phase2Method::PAP), &nPap));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PHASE2_PAP", nPap));
    napi_value nMSChap;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(Wifi::Phase2Method::MSCHAP), &nMSChap));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PHASE2_MSCHAP", nMSChap));
    napi_value nMSChapV2;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(Wifi::Phase2Method::MSCHAPV2), &nMSChapV2));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PHASE2_MSCHAPV2", nMSChapV2));
    napi_value nGtc;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(Wifi::Phase2Method::GTC), &nGtc));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PHASE2_GTC", nGtc));
    napi_value nSim;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(Wifi::Phase2Method::SIM), &nSim));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PHASE2_SIM", nSim));
    napi_value nAka;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(Wifi::Phase2Method::AKA), &nAka));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PHASE2_AKA", nAka));
    napi_value nAkaPrime;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(Wifi::Phase2Method::AKA_PRIME), &nAkaPrime));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "PHASE2_AKA_PRIME", nAkaPrime));
#endif
}

napi_value WifiManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_value nWifiSecurityType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nWifiSecurityType));
    CreateWifiSecurityTypeObject(env, nWifiSecurityType);

    napi_value nIpType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nIpType));
    CreateIpTypeObject(env, nIpType);

    napi_value nEapMethod = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nEapMethod));
    CreateEapMethodObject(env, nEapMethod);

    napi_value nPhase2Method = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nPhase2Method));
    CreatePhase2MethodObject(env, nPhase2Method);

    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("isWifiActive", IsWifiActive),
        DECLARE_NAPI_FUNCTION("setWifiProfile", SetWifiProfile),
        DECLARE_NAPI_FUNCTION("setWifiDisabled", SetWifiDisabled),
        DECLARE_NAPI_FUNCTION("isWifiDisabled", IsWifiDisabled),
        DECLARE_NAPI_FUNCTION("isWifiActiveSync", IsWifiActiveSync),
        DECLARE_NAPI_FUNCTION("setWifiProfileSync", SetWifiProfileSync),

        DECLARE_NAPI_PROPERTY("WifiSecurityType", nWifiSecurityType),
        DECLARE_NAPI_PROPERTY("IpType", nIpType),
        DECLARE_NAPI_PROPERTY("EapMethod", nEapMethod),
        DECLARE_NAPI_PROPERTY("Phase2Method", nPhase2Method)
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value WifiManagerAddon::IsWifiActive(napi_env env, napi_callback_info info)
{
    EDMLOGI("WifiManagerAddon::IsWifiActive called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    if (argc > ARGS_SIZE_ONE) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_ONE], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncIsWifiActiveCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncIsWifiActiveCallbackInfo> callbackPtr {asyncCallbackInfo};
    bool ret = ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    EDMLOGD("IsWifiActive: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    if (argc > ARGS_SIZE_ONE) {
        EDMLOGD("NAPI_IsWifiActive argc == ARGS_SIZE_TWO");
        napi_create_reference(env, argv[ARR_INDEX_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "IsWifiActive",
        NativeIsWifiActive, NativeBoolCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

napi_value WifiManagerAddon::SetWifiDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("WifiManagerAddon::SetWifiDisabled called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_boolean), "parameter bool error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "SetWifiDisabled: elementName.bundlename: %{public}s, "
        "elementName.abilityname: %{public}s",
        elementName.GetBundleName().c_str(),
        elementName.GetAbilityName().c_str());
    bool isDisabled = false;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, isDisabled, argv[ARR_INDEX_ONE]),
        "parameter isDisabled error");
    int32_t ret = WifiManagerProxy::GetWifiManagerProxy()->SetWifiDisabled(elementName, isDisabled);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value WifiManagerAddon::IsWifiDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("WifiManagerAddon::IsWifiDisabled called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool hasAdmin = false;
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, CheckGetPolicyAdminParam(env, argv[ARR_INDEX_ZERO], hasAdmin, elementName),
        "param admin need be null or want");
    bool isDisabled = false;
    int32_t ret = ERR_OK;
    if (hasAdmin) {
        ret = WifiManagerProxy::GetWifiManagerProxy()->IsWifiDisabled(&elementName, isDisabled);
    } else {
        ret = WifiManagerProxy::GetWifiManagerProxy()->IsWifiDisabled(nullptr, isDisabled);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    napi_get_boolean(env, isDisabled, &result);
    return result;
}

napi_value WifiManagerAddon::SetWifiProfile(napi_env env, napi_callback_info info)
{
#ifdef WIFI_EDM_ENABLE
    EDMLOGI("WifiManagerAddon::SetWifiProfile called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_ONE], napi_object);
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
    }
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    auto asyncCallbackInfo = new (std::nothrow) AsyncSetWifiProfileCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncSetWifiProfileCallbackInfo> callbackPtr {asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env,
        ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]), "element name param error");
    EDMLOGD("SetWifiProfile: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    ASSERT_AND_THROW_PARAM_ERROR(env,
        JsObjToDeviceConfig(env, argv[ARR_INDEX_ONE], asyncCallbackInfo->wifiDeviceConfig), "wifiProfile param error");
    if (argc > ARGS_SIZE_TWO) {
        EDMLOGD("NAPI_SetWifiProfile argc == ARGS_SIZE_THREE");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    napi_value asyncWorkReturn = HandleAsyncWork(env, asyncCallbackInfo, "SetWifiProfile",
        NativeSetWifiProfile, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
#else
    EDMLOGW("WifiManagerAddon::SetWifiProfile Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

#ifdef WIFI_EDM_ENABLE
void WifiManagerAddon::NativeSetWifiProfile(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeSetWifiProfile called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncSetWifiProfileCallbackInfo *asyncCallbackInfo = static_cast<AsyncSetWifiProfileCallbackInfo *>(data);
    auto wifiManagerProxy = WifiManagerProxy::GetWifiManagerProxy();
    if (wifiManagerProxy == nullptr) {
        EDMLOGE("can not get WifiManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = wifiManagerProxy->SetWifiProfile(asyncCallbackInfo->elementName,
        asyncCallbackInfo->wifiDeviceConfig);
}
#endif

void WifiManagerAddon::NativeIsWifiActive(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeIsWifiActive called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncIsWifiActiveCallbackInfo *asyncCallbackInfo = static_cast<AsyncIsWifiActiveCallbackInfo *>(data);
    auto wifiManagerProxy = WifiManagerProxy::GetWifiManagerProxy();
    if (wifiManagerProxy == nullptr) {
        EDMLOGE("can not get WifiManagerProxy");
        return;
    }
    asyncCallbackInfo->ret = wifiManagerProxy->IsWifiActive(asyncCallbackInfo->elementName,
        asyncCallbackInfo->boolRet);
}
#ifdef WIFI_EDM_ENABLE
bool WifiManagerAddon::JsObjToDeviceConfig(napi_env env, napi_value object, Wifi::WifiDeviceConfig &config)
{
    int32_t type = static_cast<int32_t>(SecurityType::SEC_TYPE_INVALID);
    int32_t ipType = static_cast<int32_t>(IpType::UNKNOWN);
    /* "creatorUid" "disableReason" "randomMacType" "randomMacAddr" is not supported currently */
    if (!JsObjectToString(env, object, "ssid", true, config.ssid) ||
        !JsObjectToString(env, object, "bssid", false, config.bssid) ||
        !JsObjectToString(env, object, "preSharedKey", true, config.preSharedKey) ||
        !JsObjectToBool(env, object, "isHiddenSsid", false, config.hiddenSSID) ||
        !JsObjectToInt(env, object, "securityType", true, type) ||
        !JsObjectToInt(env, object, "netId", false, config.networkId) ||
        !JsObjectToInt(env, object, "ipType", false, ipType) ||
        !ProcessIpType(ipType, env, object, config.wifiIpConfig)) {
        return false;
    }
    ConvertEncryptionMode(type, config);
    if (type == static_cast<int32_t>(SecurityType::SEC_TYPE_EAP)) {
        return ProcessEapConfig(env, object, config.wifiEapConfig);
    }
    return true;
}

void WifiManagerAddon::ConvertEncryptionMode(int32_t securityType, Wifi::WifiDeviceConfig &config)
{
    switch (securityType) {
        case static_cast<int32_t>(SecurityType::SEC_TYPE_OPEN):
            config.keyMgmt = Wifi::KEY_MGMT_NONE;
            break;
        case static_cast<int32_t>(SecurityType::SEC_TYPE_WEP):
            config.keyMgmt = Wifi::KEY_MGMT_WEP;
            config.wepKeys[0] = config.preSharedKey;
            config.wepTxKeyIndex = 0;
            config.preSharedKey = "";
            break;
        case static_cast<int32_t>(SecurityType::SEC_TYPE_PSK):
            config.keyMgmt = Wifi::KEY_MGMT_WPA_PSK;
            break;
        case static_cast<int32_t>(SecurityType::SEC_TYPE_SAE):
            config.keyMgmt = Wifi::KEY_MGMT_SAE;
            break;
        case static_cast<int32_t>(SecurityType::SEC_TYPE_EAP):
            config.keyMgmt = Wifi::KEY_MGMT_EAP;
            break;
        default:
            config.keyMgmt = Wifi::KEY_MGMT_NONE;
            break;
    }
}

bool WifiManagerAddon::ProcessIpType(int32_t ipType, napi_env env, napi_value object, Wifi::WifiIpConfig &ipConfig)
{
    switch (ipType) {
        case static_cast<int32_t>(IpType::DHCP):
            ipConfig.assignMethod = Wifi::AssignIpMethod::DHCP;
            break;
        case static_cast<int32_t>(IpType::STATIC):
            ipConfig.assignMethod = Wifi::AssignIpMethod::STATIC;
            break;
        default:
            ipConfig.assignMethod = Wifi::AssignIpMethod::UNASSIGNED;
            break;
    }
    if (ipType == static_cast<int32_t>(IpType::STATIC) && !ConfigStaticIp(env, object, ipConfig)) {
        return false;
    }
    return true;
}

bool WifiManagerAddon::ConfigStaticIp(napi_env env, napi_value object, Wifi::WifiIpConfig &ipConfig)
{
    napi_value staticIp;
    napi_value dnsServers;
    napi_value primaryDns;
    napi_value secondDns;
    if (!GetJsProperty(env, object, "staticIp", staticIp) ||
        !JsObjectToUint(env, staticIp, "ipAddress", true,
        ipConfig.staticIpAddress.ipAddress.address.addressIpv4) ||
        !JsObjectToUint(env, staticIp, "gateway", true,
        ipConfig.staticIpAddress.gateway.addressIpv4) ||
        !JsObjectToInt(env, staticIp, "prefixLength", true,
        ipConfig.staticIpAddress.ipAddress.prefixLength) ||
        !GetJsProperty(env, staticIp, "dnsServers", dnsServers)) {
        return false;
    }
    ipConfig.staticIpAddress.ipAddress.address.family = 0;
    uint32_t arrayLength = 0;
    const uint32_t DNS_NUM = 2;
    napi_get_array_length(env, dnsServers, &arrayLength);
    if (arrayLength != DNS_NUM) {
        EDMLOGI("ConfigStaticIp, It needs two dns servers.");
        return false;
    }
    napi_get_element(env, dnsServers, 0, &primaryDns);
    napi_get_element(env, dnsServers, 1, &secondDns);
    napi_get_value_uint32(env, primaryDns, &ipConfig.staticIpAddress.dnsServer1.addressIpv4);
    napi_get_value_uint32(env, secondDns, &ipConfig.staticIpAddress.dnsServer2.addressIpv4);
    return true;
}

bool WifiManagerAddon::ProcessEapConfig(napi_env env, napi_value object, Wifi::WifiEapConfig &eapConfig)
{
    napi_value napiEap;
    int32_t eapMethod = static_cast<int32_t>(EapMethod::EAP_NONE);
    if (!GetJsProperty(env, object, "eapProfile", napiEap) ||
        !JsObjectToInt(env, napiEap, "eapMethod", true, eapMethod)) {
        return false;
    }
    switch (eapMethod) {
        case static_cast<int32_t>(EapMethod::EAP_PEAP):
            ProcessEapPeapConfig(env, napiEap, eapConfig);
            break;
        case static_cast<int32_t>(EapMethod::EAP_TLS):
            ProcessEapTlsConfig(env, napiEap, eapConfig);
            break;
        default:
            EDMLOGI("EapMethod: %{public}d unsupported", eapMethod);
            return false;
    }
    return true;
}

bool WifiManagerAddon::ProcessEapPeapConfig(napi_env env, napi_value object, Wifi::WifiEapConfig &eapConfig)
{
    eapConfig.eap = Wifi::EAP_METHOD_PEAP;
    int32_t phase2 = static_cast<int32_t>(Wifi::Phase2Method::NONE);
    if (!JsObjectToString(env, object, "identity", true, eapConfig.identity) ||
        !JsObjectToString(env, object, "password", true, eapConfig.password) ||
        !JsObjectToInt(env, object, "phase2Method", true, phase2)) {
        return false;
    }
    MessageParcelUtils::ProcessPhase2Method(phase2, eapConfig);
    return true;
}

bool WifiManagerAddon::ProcessEapTlsConfig(napi_env env, napi_value object, Wifi::WifiEapConfig &eapConfig)
{
    eapConfig.eap = Wifi::EAP_METHOD_TLS;
    std::tuple<int, bool> charArrayProp = {WIFI_PASSWORD_LEN, true};
    if (!JsObjectToString(env, object, "identity", true, eapConfig.identity) ||
        !JsObjectToCharArray(env, object, "certPassword", charArrayProp, eapConfig.certPassword) ||
        !JsObjectToU8Vector(env, object, "certEntry", eapConfig.certEntry)) {
        return false;
    }
    return true;
}
#endif

napi_value WifiManagerAddon::IsWifiActiveSync(napi_env env, napi_callback_info info)
{
    EDMLOGI("WifiManagerAddon::IsWifiActiveSync called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    EDMLOGD("IsWifiActiveSync: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());

    auto wifiManagerProxy = WifiManagerProxy::GetWifiManagerProxy();
    if (wifiManagerProxy == nullptr) {
        EDMLOGE("can not get WifiManagerProxy");
        return nullptr;
    }
    bool isActive = false;
    int32_t ret = wifiManagerProxy->IsWifiActive(elementName, isActive, true);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    napi_get_boolean(env, isActive, &result);
    return result;
}

napi_value WifiManagerAddon::SetWifiProfileSync(napi_env env, napi_callback_info info)
{
#ifdef WIFI_EDM_ENABLE
    EDMLOGI("WifiManagerAddon::SetWifiProfileSync called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));

    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_object), "parameter profile error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    EDMLOGD("SetWifiProfileSync: elementName.bundleName %{public}s, elementName.abilityName:%{public}s",
        elementName.GetBundleName().c_str(), elementName.GetAbilityName().c_str());
    Wifi::WifiDeviceConfig config;
    ASSERT_AND_THROW_PARAM_ERROR(env, JsObjToDeviceConfig(env, argv[ARR_INDEX_ONE], config),
        "parameter profile parse error");

    auto wifiManagerProxy = WifiManagerProxy::GetWifiManagerProxy();
    if (wifiManagerProxy == nullptr) {
        EDMLOGE("can not get WifiManagerProxy");
        return nullptr;
    }
    int32_t ret = wifiManagerProxy->SetWifiProfile(elementName, config, true);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
#else
    EDMLOGW("WifiManagerAddon::SetWifiProfileSync Unsupported Capabilities.");
    napi_throw(env, CreateError(env, EdmReturnErrCode::INTERFACE_UNSUPPORTED));
    return nullptr;
#endif
}

static napi_module g_wifiManagerModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = WifiManagerAddon::Init,
    .nm_modname = "enterprise.wifiManager",
    .nm_priv = ((void *)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void WifiManagerRegister()
{
    napi_module_register(&g_wifiManagerModule);
}