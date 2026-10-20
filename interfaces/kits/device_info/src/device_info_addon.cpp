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

#include <memory>

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "napi_edm_adapter.h"
#include "napi_edm_error.h"

using namespace OHOS::EDM;

napi_value DeviceInfoAddon::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("getDeviceSerial", GetDeviceSerial),
        DECLARE_NAPI_FUNCTION("getDisplayVersion", GetDisplayVersion),
        DECLARE_NAPI_FUNCTION("getDeviceName", GetDeviceName),
        DECLARE_NAPI_FUNCTION("getDeviceInfo", GetDeviceInfoSync),
        DECLARE_NAPI_FUNCTION("getPatchInfo", GetPatchInfo),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

napi_value DeviceInfoAddon::GetDeviceSerial(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDeviceSerial called");
    return GetDeviceInfo(env, info, EdmInterfaceCode::GET_DEVICE_SERIAL);
}

napi_value DeviceInfoAddon::GetDisplayVersion(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDisplayVersion called");
    return GetDeviceInfo(env, info, EdmInterfaceCode::GET_DISPLAY_VERSION);
}

napi_value DeviceInfoAddon::GetDeviceName(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetDeviceName called");
    return GetDeviceInfo(env, info, EdmInterfaceCode::GET_DEVICE_NAME);
}

napi_value DeviceInfoAddon::GetDeviceInfoSync(napi_env env, napi_callback_info info)
{
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

napi_value DeviceInfoAddon::GetPatchInfo(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_GetPatchInfo called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "getPatchInfo";
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    addonMethodSign.policyCode = EdmInterfaceCode::GET_PATCH_INFO;
    addonMethodSign.errcodeType = ErrcodeType::NUMBER;
    return AddonMethodAdapterNew(env, info, addonMethodSign, NativeGetPatchInfo, NativeGetPatchInfoComplete);
}

void DeviceInfoAddon::NativeGetPatchInfo(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeGetPatchInfo called");
    if (data == nullptr) {
        EDMLOGE("NativeGetPatchInfo data is nullptr");
        return;
    }
    AdapterAddonData *asyncCallbackInfo = static_cast<AdapterAddonData *>(data);
#ifdef FEATURE_PC_ONLY
    auto deviceInfoProxy = DeviceInfoProxy::GetDeviceInfoProxy();
    if (deviceInfoProxy == nullptr) {
        EDMLOGE("NativeGetPatchInfo can not get DeviceInfoProxy");
        asyncCallbackInfo->ret = EdmReturnErrCode::EXECUTE_TIME_OUT;
        return;
    }
    asyncCallbackInfo->ret = deviceInfoProxy->GetPatchInfo(asyncCallbackInfo->data, asyncCallbackInfo->reply);
#else
    asyncCallbackInfo->ret = ERR_OK;
    asyncCallbackInfo->reply.WriteUint32(0);
#endif
}

napi_value DeviceInfoAddon::BuildPatchInfoArray(napi_env env, MessageParcel &reply)
{
    uint32_t size = 0;
    if (!reply.ReadUint32(size)) {
        EDMLOGE("BuildPatchInfoArray read size fail");
        return nullptr;
    }
    if (size > EdmConstants::PATCH_INFO_MAX_SIZE) {
        EDMLOGE("BuildPatchInfoArray size over limit: %{public}u", size);
        return nullptr;
    }
    napi_value jsList = nullptr;
    if (napi_create_array_with_length(env, size, &jsList) != napi_ok || jsList == nullptr) {
        EDMLOGE("BuildPatchInfoArray create array failed");
        return nullptr;
    }
    for (uint32_t i = 0; i < size; ++i) {
        PatchInfo info;
        if (!PatchInfo::Unmarshalling(reply, info)) {
            EDMLOGE("BuildPatchInfoArray Unmarshalling fail");
            return nullptr;
        }
        napi_value item = PatchInfoToJsObj(env, info);
        if (item == nullptr || napi_set_element(env, jsList, i, item) != napi_ok) {
            EDMLOGE("BuildPatchInfoArray set element fail");
            return nullptr;
        }
    }
    return jsList;
}

void DeviceInfoAddon::NativeGetPatchInfoComplete(napi_env env, napi_status status, void *data)
{
    EDMLOGI("NativeGetPatchInfoComplete start");
    if (data == nullptr) {
        EDMLOGE("NativeGetPatchInfoComplete data is nullptr");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AdapterAddonData *>(data);
    if (asyncCallbackInfo->deferred != nullptr) {
        if (asyncCallbackInfo->ret == ERR_OK) {
            napi_value result = BuildPatchInfoArray(env, asyncCallbackInfo->reply);
            if (result != nullptr) {
                napi_resolve_deferred(env, asyncCallbackInfo->deferred, result);
            } else {
                napi_reject_deferred(env, asyncCallbackInfo->deferred,
                    CreateError(env, EdmReturnErrCode::EXECUTE_TIME_OUT, asyncCallbackInfo->errcodeType));
            }
        } else {
            napi_reject_deferred(env, asyncCallbackInfo->deferred,
                CreateError(env, asyncCallbackInfo->ret, asyncCallbackInfo->errcodeType));
        }
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
}

napi_value DeviceInfoAddon::PatchDescriptionBodyToJsObj(napi_env env, const PatchDescriptionBody &body)
{
    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value nTitle = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, body.title.c_str(), NAPI_AUTO_LENGTH, &nTitle));
    NAPI_CALL(env, napi_set_named_property(env, value, "title", nTitle));

    napi_value nContents = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, body.contents.size(), &nContents));
    for (size_t i = 0; i < body.contents.size(); ++i) {
        napi_value item = nullptr;
        NAPI_CALL(env, napi_create_string_utf8(env, body.contents[i].c_str(), NAPI_AUTO_LENGTH, &item));
        NAPI_CALL(env, napi_set_element(env, nContents, i, item));
    }
    NAPI_CALL(env, napi_set_named_property(env, value, "contents", nContents));
    return value;
}

napi_value DeviceInfoAddon::PatchDescriptionToJsObj(napi_env env, const PatchDescription &description)
{
    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value nHeaders = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, description.headers.size(), &nHeaders));
    for (size_t i = 0; i < description.headers.size(); ++i) {
        napi_value item = nullptr;
        NAPI_CALL(env, napi_create_string_utf8(env, description.headers[i].c_str(), NAPI_AUTO_LENGTH, &item));
        NAPI_CALL(env, napi_set_element(env, nHeaders, i, item));
    }
    NAPI_CALL(env, napi_set_named_property(env, value, "headers", nHeaders));

    napi_value nBodies = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, description.bodies.size(), &nBodies));
    for (size_t i = 0; i < description.bodies.size(); ++i) {
        napi_value item = PatchDescriptionBodyToJsObj(env, description.bodies[i]);
        NAPI_CALL(env, napi_set_element(env, nBodies, i, item));
    }
    NAPI_CALL(env, napi_set_named_property(env, value, "bodies", nBodies));
    return value;
}

napi_value DeviceInfoAddon::PatchInfoToJsObj(napi_env env, const PatchInfo &patchInfo)
{
    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value nName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, patchInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL(env, napi_set_named_property(env, value, "name", nName));

    napi_value nAccountName = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, patchInfo.accountName.c_str(), NAPI_AUTO_LENGTH, &nAccountName));
    NAPI_CALL(env, napi_set_named_property(env, value, "accountName", nAccountName));

    napi_value nInstallTime = nullptr;
    NAPI_CALL(env, napi_create_int64(env, patchInfo.installTime, &nInstallTime));
    NAPI_CALL(env, napi_set_named_property(env, value, "installTime", nInstallTime));

    napi_value nDescription = PatchDescriptionToJsObj(env, patchInfo.description);
    NAPI_CALL(env, napi_set_named_property(env, value, "description", nDescription));
    return value;
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