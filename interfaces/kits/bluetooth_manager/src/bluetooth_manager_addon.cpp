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

#include "bluetooth_manager_addon.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "errors.h"
#include "hisysevent_adapter.h"
#include "js_native_api.h"
#include "napi_edm_adapter.h"
#include "napi_edm_common.h"

using namespace OHOS::EDM;

napi_value BluetoothManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("getBluetoothInfo", GetBluetoothInfo),
        DECLARE_NAPI_FUNCTION("setBluetoothDisabled", SetBluetoothDisabled),
        DECLARE_NAPI_FUNCTION("isBluetoothDisabled", IsBluetoothDisabled),
        DECLARE_NAPI_FUNCTION("addAllowedBluetoothDevices", AddAllowedBluetoothDevices),
        DECLARE_NAPI_FUNCTION("getAllowedBluetoothDevices", GetAllowedBluetoothDevices),
        DECLARE_NAPI_FUNCTION("removeAllowedBluetoothDevices", RemoveAllowedBluetoothDevices),
        DECLARE_NAPI_FUNCTION("turnOnBluetooth", TurnOnBluetooth),
        DECLARE_NAPI_FUNCTION("turnOffBluetooth", TurnOffBluetooth),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value BluetoothManagerAddon::GetBluetoothInfo(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetBluetoothInfo called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "getBluetoothInfo");
    BluetoothInfo bluetoothInfo;
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetBluetoothInfo";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t ret =
        BluetoothManagerProxy::GetBluetoothManagerProxy()->GetBluetoothInfo(adapterAddonData.data, bluetoothInfo);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    return ConvertBluetoothInfo(env, bluetoothInfo);
}

napi_value BluetoothManagerAddon::ConvertBluetoothInfo(napi_env env, BluetoothInfo &bluetoothInfo)
{
    napi_value objBluetoothInfo = nullptr;
    NAPI_CALL(env, napi_create_object(env, &objBluetoothInfo));
    napi_value napi_name;
    napi_value napi_state;
    napi_value napi_connectionState;
    NAPI_CALL(env, napi_create_string_utf8(env, bluetoothInfo.name.c_str(), bluetoothInfo.name.size(), &napi_name));
    NAPI_CALL(env, napi_create_int32(env, bluetoothInfo.state, &napi_state));
    NAPI_CALL(env, napi_create_int32(env, bluetoothInfo.connectionState, &napi_connectionState));
    NAPI_CALL(env, napi_set_named_property(env, objBluetoothInfo, "name", napi_name));
    NAPI_CALL(env, napi_set_named_property(env, objBluetoothInfo, "state", napi_state));
    NAPI_CALL(env, napi_set_named_property(env, objBluetoothInfo, "connectionState", napi_connectionState));
    return objBluetoothInfo;
}

napi_value BluetoothManagerAddon::SetBluetoothDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_SetBluetoothDisabled called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "setBluetoothDisabled");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "SetBluetoothDisabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::BOOLEAN};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.apiVersionTag = EdmConstants::PERMISSION_TAG_VERSION_11;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    int32_t retCode =
        BluetoothManagerProxy::GetBluetoothManagerProxy()->SetBluetoothDisabled(adapterAddonData.data);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
    }
    return nullptr;
}

napi_value BluetoothManagerAddon::IsBluetoothDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_IsBluetoothDisabled called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "isBluetoothDisabled");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "IsBluetoothDisabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT_NULL};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    addonMethodSign.apiVersionTag = EdmConstants::PERMISSION_TAG_VERSION_11;
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    bool isDisabled = false;
    int32_t ret =
        BluetoothManagerProxy::GetBluetoothManagerProxy()->IsBluetoothDisabled(adapterAddonData.data, isDisabled);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, isDisabled, &result));
    return result;
}

napi_value BluetoothManagerAddon::AddAllowedBluetoothDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddAllowedBluetoothDevices called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "addAllowedBluetoothDevices");
    return AddOrRemoveBluetoothDevices(env, info, "AddAllowedBluetoothDevices");
}

napi_value BluetoothManagerAddon::GetAllowedBluetoothDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetAllowedBluetoothDevices called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "getAllowedBluetoothDevices");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetAllowedBluetoothDevices";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT_NULL};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }

    std::vector<std::string> deviceIds;
    int32_t retCode =
        BluetoothManagerProxy::GetBluetoothManagerProxy()->GetAllowedBluetoothDevices(adapterAddonData.data, deviceIds);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_array(env, &result));
    for (size_t i = 0; i < deviceIds.size(); i++) {
        napi_value allowedDevices = nullptr;
        NAPI_CALL(env, napi_create_string_utf8(env, deviceIds[i].c_str(), NAPI_AUTO_LENGTH, &allowedDevices));
        NAPI_CALL(env, napi_set_element(env, result, i, allowedDevices));
    }
    return result;
}

napi_value BluetoothManagerAddon::RemoveAllowedBluetoothDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveAllowedBluetoothDevices called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "removeAllowedBluetoothDevices");
    return AddOrRemoveBluetoothDevices(env, info, "RemoveAllowedBluetoothDevices");
}

napi_value BluetoothManagerAddon::AddOrRemoveBluetoothDevices(napi_env env, napi_callback_info info,
    std::string function)
{
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "AddOrRemoveBluetoothDevices";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::ARRAY_STRING};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    std::vector<std::string> deviceIds;
    int32_t retCode = BluetoothManagerProxy::GetBluetoothManagerProxy()->
        AddOrRemoveAllowedBluetoothDevices(adapterAddonData.data, function == "AddAllowedBluetoothDevices");
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
    }
    return nullptr;
}

napi_value BluetoothManagerAddon::TurnOnBluetooth(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_TurnOnBluetooth called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "turnOnBluetooth");
    return TurnOnOrOffBluetooth(env, info, true);
}

napi_value BluetoothManagerAddon::TurnOffBluetooth(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_TurnOffBluetooth called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "turnOffBluetooth");
    return TurnOnOrOffBluetooth(env, info, false);
}

napi_value BluetoothManagerAddon::TurnOnOrOffBluetooth(napi_env env, napi_callback_info info, bool isOpen)
{
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "TurnOnOrOffBluetooth";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    adapterAddonData.data.WriteBool(isOpen);
    int32_t retCode = BluetoothManagerProxy::GetBluetoothManagerProxy()->TurnOnOrOffBluetooth(adapterAddonData.data);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
    }
    return nullptr;
}

static napi_module g_bluetoothModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = BluetoothManagerAddon::Init,
    .nm_modname = "enterprise.bluetoothManager",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void BluetoothManagerRegister()
{
    napi_module_register(&g_bluetoothModule);
}
