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
#include "js_native_api.h"
#include "napi_edm_adapter.h"
#include "napi_edm_common.h"

using namespace OHOS::EDM;

napi_value BluetoothManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_value nProtocol = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nProtocol));
    CreateProtocolObject(env, nProtocol);

    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("getBluetoothInfo", GetBluetoothInfo),
        DECLARE_NAPI_FUNCTION("setBluetoothDisabled", SetBluetoothDisabled),
        DECLARE_NAPI_FUNCTION("isBluetoothDisabled", IsBluetoothDisabled),
        DECLARE_NAPI_FUNCTION("addAllowedBluetoothDevices", AddAllowedBluetoothDevices),
        DECLARE_NAPI_FUNCTION("getAllowedBluetoothDevices", GetAllowedBluetoothDevices),
        DECLARE_NAPI_FUNCTION("removeAllowedBluetoothDevices", RemoveAllowedBluetoothDevices),
        DECLARE_NAPI_FUNCTION("addDisallowedBluetoothDevices", AddDisallowedBluetoothDevices),
        DECLARE_NAPI_FUNCTION("getDisallowedBluetoothDevices", GetDisallowedBluetoothDevices),
        DECLARE_NAPI_FUNCTION("removeDisallowedBluetoothDevices", RemoveDisallowedBluetoothDevices),
        DECLARE_NAPI_FUNCTION("turnOnBluetooth", TurnOnBluetooth),
        DECLARE_NAPI_FUNCTION("turnOffBluetooth", TurnOffBluetooth),
        DECLARE_NAPI_FUNCTION("addDisallowedBluetoothProtocols", AddDisallowedBluetoothProtocols),
        DECLARE_NAPI_FUNCTION("getDisallowedBluetoothProtocols", GetDisallowedBluetoothProtocols),
        DECLARE_NAPI_FUNCTION("removeDisallowedBluetoothProtocols", RemoveDisallowedBluetoothProtocols),

        DECLARE_NAPI_PROPERTY("Protocol", nProtocol),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value BluetoothManagerAddon::GetBluetoothInfo(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetBluetoothInfo called");
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

napi_value BluetoothManagerAddon::GetAllowedBluetoothDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetAllowedBluetoothDevices called");
    return GetBluetoothDevices(env, info, EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES);
}

napi_value BluetoothManagerAddon::GetDisallowedBluetoothDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisallowedBluetoothDevices called");
    return GetBluetoothDevices(env, info, EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES);
}

napi_value BluetoothManagerAddon::GetBluetoothDevices(napi_env env, napi_callback_info info,
    EdmInterfaceCode policyCode)
{
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetBluetoothDevices";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT_NULL};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    auto bluetoothManagerProxy = BluetoothManagerProxy::GetBluetoothManagerProxy();
    if (bluetoothManagerProxy == nullptr) {
        EDMLOGE("can not get bluetoothManagerProxy");
        return nullptr;
    }
    std::vector<std::string> deviceIds;
    int32_t retCode = bluetoothManagerProxy->GetBluetoothDevices(adapterAddonData.data, deviceIds, policyCode);
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

napi_value BluetoothManagerAddon::AddAllowedBluetoothDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddAllowedBluetoothDevices called");
    return AddOrRemoveBluetoothDevices(env, info, FuncOperateType::SET, EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES);
}

napi_value BluetoothManagerAddon::RemoveAllowedBluetoothDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveAllowedBluetoothDevices called");
    return AddOrRemoveBluetoothDevices(env, info, FuncOperateType::REMOVE,
        EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES);
}

napi_value BluetoothManagerAddon::AddDisallowedBluetoothDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddDisallowedBluetoothDevices called");
    return AddOrRemoveBluetoothDevices(env, info, FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES);
}

napi_value BluetoothManagerAddon::RemoveDisallowedBluetoothDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveDisallowedBluetoothDevices called");
    return AddOrRemoveBluetoothDevices(env, info, FuncOperateType::REMOVE,
        EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES);
}

napi_value BluetoothManagerAddon::AddOrRemoveBluetoothDevices(napi_env env, napi_callback_info info,
    FuncOperateType operateType, EdmInterfaceCode code)
{
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "AddOrRemoveBluetoothDevices";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::ARRAY_STRING};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    int32_t retCode = BluetoothManagerProxy::GetBluetoothManagerProxy()->
        AddOrRemoveBluetoothDevices(adapterAddonData.data, operateType, code);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
    }
    return nullptr;
}

napi_value BluetoothManagerAddon::TurnOnBluetooth(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_TurnOnBluetooth called");
    return TurnOnOrOffBluetooth(env, info, true);
}

napi_value BluetoothManagerAddon::TurnOffBluetooth(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_TurnOffBluetooth called");
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

napi_value BluetoothManagerAddon::AddDisallowedBluetoothProtocols(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_AddDisallowedBluetoothProtocols called");
    return AddOrRemoveDisallowedBluetoothProtocols(env, info, "AddDisallowedBluetoothProtocols");
}

napi_value BluetoothManagerAddon::GetDisallowedBluetoothProtocols(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisallowedBluetoothProtocols called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetDisallowedBluetoothProtocols";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::USERID};
    addonMethodSign.argsConvert = {nullptr, nullptr};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    std::vector<int32_t> protocols;
    int32_t retCode = BluetoothManagerProxy::GetBluetoothManagerProxy()->
        GetDisallowedBluetoothProtocols(adapterAddonData.data, protocols);
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
        return nullptr;
    }
    napi_value jsList = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, protocols.size(), &jsList));
    for (size_t i = 0; i < protocols.size(); i++) {
        napi_value item;
        NAPI_CALL(env, napi_create_int32(env, protocols[i], &item));
        NAPI_CALL(env, napi_set_element(env, jsList, i, item));
    }
    return jsList;
}

napi_value BluetoothManagerAddon::RemoveDisallowedBluetoothProtocols(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_RemoveDisallowedBluetoothProtocols called");
    return AddOrRemoveDisallowedBluetoothProtocols(env, info, "RemoveDisallowedBluetoothProtocols");
}

napi_value BluetoothManagerAddon::AddOrRemoveDisallowedBluetoothProtocols(napi_env env, napi_callback_info info,
    std::string function)
{
    EDMLOGI("NAPI_AddOrRemoveDisallowedBluetoothProtocols called");
    auto convertBtProtocol2Data = [](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) {
        std::vector<int32_t> bluetoothProtocols;
        if (!ParseIntArray(env, bluetoothProtocols, argv)) {
            EDMLOGE("NAPI_AddOrRemoveDisallowedBluetoothProtocols ParseIntArray fail");
            return false;
        }
        data.WriteInt32Vector(bluetoothProtocols);
        return true;
    };
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "AddOrRemoveDisallowedBluetoothProtocols";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::USERID, EdmAddonCommonType::CUSTOM};
    addonMethodSign.argsConvert = {nullptr, nullptr, convertBtProtocol2Data};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    int32_t retCode = BluetoothManagerProxy::GetBluetoothManagerProxy()->
        AddOrRemoveDisallowedBluetoothProtocols(adapterAddonData.data, function == "AddDisallowedBluetoothProtocols");
    if (FAILED(retCode)) {
        napi_throw(env, CreateError(env, retCode));
    }
    return nullptr;
}

void BluetoothManagerAddon::CreateProtocolObject(napi_env env, napi_value value)
{
    napi_value nGatt;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(BtProtocol::GATT), &nGatt));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GATT", nGatt));
    napi_value nSpp;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(BtProtocol::SPP), &nSpp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SPP", nSpp));
    napi_value nOpp;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(BtProtocol::OPP), &nOpp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "OPP", nOpp));
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
