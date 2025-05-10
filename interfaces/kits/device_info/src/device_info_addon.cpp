/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "device_info_addon.h"

#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "hisysevent_adapter.h"
#include "napi_edm_adapter.h"

using namespace OHOS::EDM;

napi_value DeviceInfoAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("getDeviceSerial", GetDeviceSerial),
        DECLARE_NAPI_FUNCTION("getDisplayVersion", GetDisplayVersion),
        DECLARE_NAPI_FUNCTION("getDeviceName", GetDeviceName),
        DECLARE_NAPI_FUNCTION("getDeviceInfo", GetDeviceInfoSync),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value DeviceInfoAddon::GetDeviceSerial(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDeviceSerial called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "getDeviceSerial");
    return GetDeviceInfo(env, info, EdmInterfaceCode::GET_DEVICE_SERIAL);
}

napi_value DeviceInfoAddon::GetDisplayVersion(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisplayVersion called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "getDisplayVersion");
    return GetDeviceInfo(env, info, EdmInterfaceCode::GET_DISPLAY_VERSION);
}

napi_value DeviceInfoAddon::GetDeviceName(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDeviceName called");
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "getDeviceName");
    return GetDeviceInfo(env, info, EdmInterfaceCode::GET_DEVICE_NAME);
}

napi_value DeviceInfoAddon::GetDeviceInfoSync(napi_env env, napi_callback_info info)
{
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "getDeviceInfoSync");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetDeviceInfoSync";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::STRING};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    std::string deviceInfo;
    int32_t ret = DeviceInfoProxy::GetDeviceInfoProxy()->GetDeviceInfo(adapterAddonData.data,
        "", EdmInterfaceCode::GET_DEVICE_INFO, deviceInfo);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value napiInfo;
    NAPI_CALL(env, napi_create_string_utf8(env, deviceInfo.c_str(), NAPI_AUTO_LENGTH, &napiInfo));
    return napiInfo;
}

napi_value DeviceInfoAddon::GetDeviceInfo(napi_env env, napi_callback_info info, int code)
{
    HiSysEventAdapter::ReportEdmEvent(ReportType::EDM_FUNC_EVENT, "getDeviceInfo");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "GetDeviceInfo";
    addonMethodSign.policyCode = code;
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    return AddonMethodAdapter(env, info, addonMethodSign, NativeGetDeviceInfo, NativeStringCallbackComplete);
}

void DeviceInfoAddon::NativeGetDeviceInfo(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeGetDeviceInfo called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AdapterAddonData *asyncCallbackInfo = static_cast<AdapterAddonData *>(data);
    auto deviceInfoProxy = DeviceInfoProxy::GetDeviceInfoProxy();
    if (deviceInfoProxy == nullptr) {
        EDMLOGE("can not get DeviceInfoProxy");
        return;
    }
    switch (asyncCallbackInfo->policyCode) {
        case static_cast<int32_t>(EdmInterfaceCode::GET_DEVICE_SERIAL):
            asyncCallbackInfo->ret =
                deviceInfoProxy->GetDeviceSerial(asyncCallbackInfo->data, asyncCallbackInfo->stringRet);
            break;
        case static_cast<int32_t>(EdmInterfaceCode::GET_DISPLAY_VERSION):
            asyncCallbackInfo->ret =
                deviceInfoProxy->GetDisplayVersion(asyncCallbackInfo->data, asyncCallbackInfo->stringRet);
            break;
        case static_cast<int32_t>(EdmInterfaceCode::GET_DEVICE_NAME):
            asyncCallbackInfo->ret =
                deviceInfoProxy->GetDeviceName(asyncCallbackInfo->data, asyncCallbackInfo->stringRet);
            break;
        default:
            asyncCallbackInfo->ret = EdmReturnErrCode::INTERFACE_UNSUPPORTED;
            EDMLOGE("NAPI_GetDeviceInfo failed");
            return;
    }
}

static napi_module g_deviceInfoModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = DeviceInfoAddon::Init,
    .nm_modname = "enterprise.deviceInfo",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void DeviceInfoRegister()
{
    napi_module_register(&g_deviceInfoModule);
}