/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "usb_manager_addon.h"

#include "edm_log.h"
#include "usb_manager_proxy.h"

using namespace OHOS::EDM;

napi_value UsbManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_value policyValue = nullptr;
    NAPI_CALL(env, napi_create_object(env, &policyValue));
    CreateUsbPolicyEnum(env, policyValue);
    napi_property_descriptor property[] = {
        DECLARE_NAPI_PROPERTY("UsbPolicy", policyValue),
        DECLARE_NAPI_FUNCTION("setUsbPolicy", SetUsbPolicy),
        DECLARE_NAPI_FUNCTION("disableUsb", DisableUsb),
        DECLARE_NAPI_FUNCTION("isUsbDisabled", IsUsbDisabled),
        DECLARE_NAPI_FUNCTION("addAllowedUsbDevices", AddAllowedUsbDevices),
        DECLARE_NAPI_FUNCTION("removeAllowedUsbDevices", RemoveAllowedUsbDevices),
        DECLARE_NAPI_FUNCTION("getAllowedUsbDevices", GetAllowedUsbDevices),
        DECLARE_NAPI_FUNCTION("setUsbStorageDeviceAccessPolicy", SetUsbStorageDeviceAccessPolicy),
        DECLARE_NAPI_FUNCTION("getUsbStorageDeviceAccessPolicy", GetUsbStorageDeviceAccessPolicy),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

void UsbManagerAddon::CreateUsbPolicyEnum(napi_env env, napi_value value)
{
    napi_value readWrite;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, EdmConstants::STORAGE_USB_POLICY_READ_WRITE, &readWrite));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "READ_WRITE", readWrite));

    napi_value readOnly;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, EdmConstants::STORAGE_USB_POLICY_READ_ONLY, &readOnly));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "READ_ONLY", readOnly));

    napi_value disabled;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, EdmConstants::STORAGE_USB_POLICY_DISABLED, &disabled));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DISABLED", disabled));
}

napi_value UsbManagerAddon::SetUsbPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::SetUsbPolicy called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool hasAdmin = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, hasAdmin, "type admin error");
    bool usbPolicy = MatchValueType(env, argv[ARR_INDEX_ONE], napi_number);
    ASSERT_AND_THROW_PARAM_ERROR(env, usbPolicy, "type usbPolicy error");
    if (argc > ARGS_SIZE_TWO) {
        bool hasCallback = MatchValueType(env, argv[ARR_INDEX_TWO], napi_function);
        ASSERT_AND_THROW_PARAM_ERROR(env, hasCallback, "type callback error");
    }

    auto asyncCallbackInfo = new (std::nothrow) AsyncSetUsbPolicyCallbackInfo();
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncSetUsbPolicyCallbackInfo> callbackPtr{asyncCallbackInfo};
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, asyncCallbackInfo->elementName, argv[ARR_INDEX_ZERO]),
        "element name param error");
    EDMLOGD(
        "SetUsbPolicy: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        asyncCallbackInfo->elementName.GetBundleName().c_str(),
        asyncCallbackInfo->elementName.GetAbilityName().c_str());
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, asyncCallbackInfo->policy, argv[ARR_INDEX_ONE]),
        "wifiProfile param error");
    if (argc > ARGS_SIZE_TWO) {
        EDMLOGD("NAPI_SetUsbPolicy argc == ARGS_SIZE_THREE");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback);
    }
    bool existUsbPolicy = std::any_of(std::begin(USB_POLICY), std::end(USB_POLICY),
        [&](int item) { return item == asyncCallbackInfo->policy; });
    ASSERT_AND_THROW_PARAM_ERROR(env, existUsbPolicy, "usb policy value error");
    napi_value asyncWorkReturn =
        HandleAsyncWork(env, asyncCallbackInfo, "SetUsbPolicy", NativeSetUsbPolicy, NativeVoidCallbackComplete);
    callbackPtr.release();
    return asyncWorkReturn;
}

void UsbManagerAddon::NativeSetUsbPolicy(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeSetUsbPolicy called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AsyncSetUsbPolicyCallbackInfo *asyncCallbackInfo = static_cast<AsyncSetUsbPolicyCallbackInfo *>(data);
    switch (asyncCallbackInfo->policy) {
        case EdmConstants::STORAGE_USB_POLICY_READ_WRITE:
            asyncCallbackInfo->ret =
                UsbManagerProxy::GetUsbManagerProxy()->SetUsbReadOnly(asyncCallbackInfo->elementName, false);
            break;
        case EdmConstants::STORAGE_USB_POLICY_READ_ONLY:
            asyncCallbackInfo->ret =
                UsbManagerProxy::GetUsbManagerProxy()->SetUsbReadOnly(asyncCallbackInfo->elementName, true);
            break;
        default:
            asyncCallbackInfo->ret = EdmReturnErrCode::PARAM_ERROR;
            break;
    }
}

napi_value UsbManagerAddon::DisableUsb(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::DisableUsb called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_boolean),
        "parameter disallow error");

    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    bool disable = false;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseBool(env, disable, argv[ARR_INDEX_ONE]), "parameter disallow parse error");

    auto usbManagerProxy = UsbManagerProxy::GetUsbManagerProxy();
    if (usbManagerProxy == nullptr) {
        EDMLOGE("can not get usbManagerProxy");
        return nullptr;
    }
    EDMLOGI("UsbManagerAddon::DisableUsb: %{public}d", disable);
    int32_t ret = usbManagerProxy->DisableUsb(elementName, disable);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value UsbManagerAddon::IsUsbDisabled(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::IsUsbDisabled called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
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
        ret = UsbManagerProxy::GetUsbManagerProxy()->IsUsbDisabled(&elementName, isDisabled);
    } else {
        ret = UsbManagerProxy::GetUsbManagerProxy()->IsUsbDisabled(nullptr, isDisabled);
    }
    EDMLOGI("UsbManagerAddon::IsUsbDisabled return: %{public}d", isDisabled);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    napi_get_boolean(env, isDisabled, &result);
    return result;
}

napi_value UsbManagerAddon::AddAllowedUsbDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::AddAllowedUsbDevices called");
    return AddOrRemoveAllowedUsbDevices(env, info, true);
}

napi_value UsbManagerAddon::RemoveAllowedUsbDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::RemoveAllowedUsbDevices called");
    return AddOrRemoveAllowedUsbDevices(env, info, false);
}

napi_value UsbManagerAddon::AddOrRemoveAllowedUsbDevices(napi_env env, napi_callback_info info, bool isAdd)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_object),
        "parameter usbDeviceIds error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    std::vector<UsbDeviceId> usbDeviceIds;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseUsbDevicesArray(env, usbDeviceIds, argv[ARR_INDEX_ONE]),
        "parameter usbDeviceIds error");

    auto usbManagerProxy = UsbManagerProxy::GetUsbManagerProxy();
    if (usbManagerProxy == nullptr) {
        EDMLOGE("can not get usbManagerProxy");
        return nullptr;
    }
    int32_t ret = ERR_OK;
    if (isAdd) {
        ret = usbManagerProxy->AddAllowedUsbDevices(elementName, usbDeviceIds);
    } else {
        ret = usbManagerProxy->RemoveAllowedUsbDevices(elementName, usbDeviceIds);
    }
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

bool UsbManagerAddon::ParseUsbDevicesArray(napi_env env, std::vector<UsbDeviceId> &usbDeviceIds, napi_value object)
{
    bool isArray = false;
    napi_is_array(env, object, &isArray);
    if (!isArray) {
        return false;
    }
    uint32_t arrayLength = 0;
    napi_get_array_length(env, object, &arrayLength);
    for (uint32_t i = 0; i < arrayLength; i++) {
        napi_value value = nullptr;
        napi_get_element(env, object, i, &value);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if (valueType != napi_object) {
            usbDeviceIds.clear();
            return false;
        }
        UsbDeviceId usbDeviceId;
        if (!GetUsbDeviceIdFromNAPI(env, value, usbDeviceId)) {
            usbDeviceIds.clear();
            return false;
        }
        usbDeviceIds.push_back(usbDeviceId);
    }
    return true;
}

bool UsbManagerAddon::GetUsbDeviceIdFromNAPI(napi_env env, napi_value value, UsbDeviceId &usbDeviceId)
{
    int32_t vendorId = 0;
    if (!JsObjectToInt(env, value, "vendorId", true, vendorId)) {
        EDMLOGE("Add/RemoveAllowedUsbDevices vendorId parse error!");
        return false;
    }
    int32_t productId = 0;
    if (!JsObjectToInt(env, value, "productId", true, productId)) {
        EDMLOGE("Add/RemoveAllowedUsbDevices productId parse error!");
        return false;
    }
    usbDeviceId.SetVendorId(vendorId);
    usbDeviceId.SetProductId(productId);
    EDMLOGD("GetUsbDeviceIdFromNAPI vendorId: %{public}d, productId: %{public}d", vendorId, productId);
    return true;
}

napi_value UsbManagerAddon::GetAllowedUsbDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::GetAllowedUsbDevices called");
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

    auto usbManagerProxy = UsbManagerProxy::GetUsbManagerProxy();
    if (usbManagerProxy == nullptr) {
        EDMLOGE("can not get usbManagerProxy");
        return nullptr;
    }
    std::vector<UsbDeviceId> usbDeviceIds;
    int32_t ret = usbManagerProxy->GetAllowedUsbDevices(elementName, usbDeviceIds);
    EDMLOGI("UsbManagerAddon::GetAllowedUsbDevices usbDeviceIds return size: %{public}zu", usbDeviceIds.size());
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value jsList = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, usbDeviceIds.size(), &jsList));
    for (size_t i = 0; i < usbDeviceIds.size(); i++) {
        napi_value item = UsbDeviceIdToJsObj(env, usbDeviceIds[i]);
        NAPI_CALL(env, napi_set_element(env, jsList, i, item));
    }
    return jsList;
}

napi_value UsbManagerAddon::UsbDeviceIdToJsObj(napi_env env, const UsbDeviceId &usbDeviceId)
{
    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value vendorId = nullptr;
    NAPI_CALL(env, napi_create_int32(env, usbDeviceId.GetVendorId(), &vendorId));
    NAPI_CALL(env, napi_set_named_property(env, value, "vendorId", vendorId));

    napi_value productId = nullptr;
    NAPI_CALL(env, napi_create_int32(env, usbDeviceId.GetProductId(), &productId));
    NAPI_CALL(env, napi_set_named_property(env, value, "productId", productId));

    return value;
}

napi_value UsbManagerAddon::SetUsbStorageDeviceAccessPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::SetUsbStorageDeviceAccessPolicy called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object), "parameter admin error");
    ASSERT_AND_THROW_PARAM_ERROR(env, MatchValueType(env, argv[ARR_INDEX_ONE], napi_number),
        "parameter usbPolicy error");
    OHOS::AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]),
        "parameter admin parse error");
    int32_t usbPolicy = EdmConstants::STORAGE_USB_POLICY_READ_WRITE;
    ASSERT_AND_THROW_PARAM_ERROR(env, ParseInt(env, usbPolicy, argv[ARR_INDEX_ONE]), "parameter type parse error");
    bool existUsbPolicy = std::any_of(std::begin(USB_POLICY), std::end(USB_POLICY),
        [&](int item) { return item == usbPolicy; });
    ASSERT_AND_THROW_PARAM_ERROR(env, existUsbPolicy, "parameter usbPolicy value error");

    auto usbManagerProxy = UsbManagerProxy::GetUsbManagerProxy();
    if (usbManagerProxy == nullptr) {
        EDMLOGE("can not get usbManagerProxy");
        return nullptr;
    }
    EDMLOGI("UsbManagerAddon::SetUsbStorageDeviceAccessPolicy: %{public}d", usbPolicy);
    int32_t ret = usbManagerProxy->SetUsbStorageDeviceAccessPolicy(elementName, usbPolicy);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value UsbManagerAddon::GetUsbStorageDeviceAccessPolicy(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::SetUsbStorageDeviceAccessPolicy called");
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

    int32_t usbPolicy = EdmConstants::STORAGE_USB_POLICY_READ_WRITE;
    auto usbManagerProxy = UsbManagerProxy::GetUsbManagerProxy();
    if (usbManagerProxy == nullptr) {
        EDMLOGE("can not get usbManagerProxy");
        return nullptr;
    }
    int32_t ret = usbManagerProxy->GetUsbStorageDeviceAccessPolicy(elementName, usbPolicy);
    EDMLOGI("UsbManagerAddon::GetUsbStorageDeviceAccessPolicy return: %{public}d", usbPolicy);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value result = nullptr;
    napi_create_int32(env, usbPolicy, &result);
    return result;
}

static napi_module g_usbManagerModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = UsbManagerAddon::Init,
    .nm_modname = "enterprise.usbManager",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void UsbManagerRegister()
{
    napi_module_register(&g_usbManagerModule);
}