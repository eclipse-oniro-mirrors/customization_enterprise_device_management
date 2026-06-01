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
#include "usb_manager_addon.h"

#include "edm_log.h"
#include "usb_manager_proxy.h"

#include "napi_edm_adapter.h"

using namespace OHOS::EDM;

napi_value UsbManagerAddon::Init(napi_env env, napi_value exports)
{
    napi_value policyValue = nullptr;
    NAPI_CALL(env, napi_create_object(env, &policyValue));
    CreateUsbPolicyEnum(env, policyValue);

    napi_value descriptorValue = nullptr;
    NAPI_CALL(env, napi_create_object(env, &descriptorValue));
    CreateDescriptorEnum(env, descriptorValue);

    napi_property_descriptor property[] = {
        DECLARE_NAPI_PROPERTY("UsbPolicy", policyValue),
        DECLARE_NAPI_PROPERTY("Descriptor", descriptorValue),
        DECLARE_NAPI_FUNCTION("setUsbPolicy", SetUsbPolicy),
        DECLARE_NAPI_FUNCTION("disableUsb", DisableUsb),
        DECLARE_NAPI_FUNCTION("isUsbDisabled", IsUsbDisabled),
        DECLARE_NAPI_FUNCTION("addAllowedUsbDevices", AddAllowedUsbDevices),
        DECLARE_NAPI_FUNCTION("removeAllowedUsbDevices", RemoveAllowedUsbDevices),
        DECLARE_NAPI_FUNCTION("getAllowedUsbDevices", GetAllowedUsbDevices),
        DECLARE_NAPI_FUNCTION("setUsbStorageDeviceAccessPolicy", SetUsbStorageDeviceAccessPolicy),
        DECLARE_NAPI_FUNCTION("getUsbStorageDeviceAccessPolicy", GetUsbStorageDeviceAccessPolicy),
        DECLARE_NAPI_FUNCTION("addDisallowedUsbDevices", AddDisallowedUsbDevices),
        DECLARE_NAPI_FUNCTION("removeDisallowedUsbDevices", RemoveDisallowedUsbDevices),
        DECLARE_NAPI_FUNCTION("getDisallowedUsbDevices", GetDisallowedUsbDevices),
        DECLARE_NAPI_FUNCTION("addDisallowedPermissiveUsbDevices", AddDisallowedPermissiveUsbDevices),
        DECLARE_NAPI_FUNCTION("removeDisallowedPermissiveUsbDevices", RemoveDisallowedPermissiveUsbDevices),
        DECLARE_NAPI_FUNCTION("getDisallowedPermissiveUsbDevices", GetDisallowedPermissiveUsbDevices),
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

void UsbManagerAddon::CreateDescriptorEnum(napi_env env, napi_value value)
{
    napi_value interfaceDescriptor;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, EdmConstants::USB_INTERFACE_DESCRIPTOR, &interfaceDescriptor));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "INTERFACE", interfaceDescriptor));

    napi_value deviceDescriptor;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, EdmConstants::USB_DEVICE_DESCRIPTOR, &deviceDescriptor));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DEVICE", deviceDescriptor));
}

napi_value UsbManagerAddon::SetUsbPolicy(napi_env env, napi_callback_info info)
{
    auto convertpolicy2Data = [](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) -> ErrCode {
        bool usbPolicy = MatchValueType(env, argv, napi_number);
        if (!usbPolicy) {
            EDMLOGE("type usbPolicy error");
            return EdmReturnErrCode::PARAM_ERROR;
        }
        int32_t policy = EdmConstants::STORAGE_USB_POLICY_DISABLED;
        if (!ParseInt(env, policy, argv)) {
            EDMLOGE("policy param error");
            return EdmReturnErrCode::PARAM_ERROR;
        }
        const int32_t readOnly = 1;
        const int32_t readWrite = 0;
        switch (policy) {
            case EdmConstants::STORAGE_USB_POLICY_READ_WRITE:
                data.WriteInt32(readWrite);
                break;
            case EdmConstants::STORAGE_USB_POLICY_READ_ONLY:
                data.WriteInt32(readOnly);
                break;
            default:
                return EdmReturnErrCode::PARAM_ERROR;
        }
        return ERR_OK;
    };
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "setUsbPolicy";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::CUSTOM};
    addonMethodSign.argsConvert = {nullptr, convertpolicy2Data};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    return AddonMethodAdapter(env, info, addonMethodSign, NativeSetUsbPolicy, NativeVoidCallbackComplete);
}

void UsbManagerAddon::NativeSetUsbPolicy(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeSetUsbPolicy called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AdapterAddonData *asyncCallbackInfo = static_cast<AdapterAddonData *>(data);
    asyncCallbackInfo->ret =
                UsbManagerProxy::GetUsbManagerProxy()->SetUsbReadOnly(asyncCallbackInfo->data);
}

napi_value UsbManagerAddon::DisableUsb(napi_env env, napi_callback_info info)
{
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "disableUsb";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::BOOLEAN};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.apiVersionTag = EdmConstants::PERMISSION_TAG_VERSION_11;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }

    auto usbManagerProxy = UsbManagerProxy::GetUsbManagerProxy();
    if (usbManagerProxy == nullptr) {
        EDMLOGE("can not get usbManagerProxy");
        return nullptr;
    }
    int32_t ret = usbManagerProxy->DisableUsb(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value UsbManagerAddon::IsUsbDisabled(napi_env env, napi_callback_info info)
{
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "isUsbDisabled";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT_NULL};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    addonMethodSign.apiVersionTag = EdmConstants::PERMISSION_TAG_VERSION_11;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    bool isDisabled = false;
    int32_t ret = ERR_OK;
    ret = UsbManagerProxy::GetUsbManagerProxy()->IsUsbDisabled(adapterAddonData.data, isDisabled);
    EDMLOGI("UsbManagerAddon::IsUsbDisabled return: %{public}d", isDisabled);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, isDisabled, &result));
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
    auto convertUsbDeviceIds2Data = [](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) -> ErrCode {
            std::vector<UsbDeviceId> usbDeviceIds;
            if (!ParseUsbDevicesArray(env, usbDeviceIds, argv)) {
                EDMLOGE("parameter type parse error");
                return EdmReturnErrCode::PARAM_ERROR;
            }
            data.WriteUint32(usbDeviceIds.size());
            for (const auto &usbDeviceId : usbDeviceIds) {
                if (!usbDeviceId.Marshalling(data)) {
                    EDMLOGE("UsbManagerProxy AddAllowedUsbDevices: write parcel failed!");
                    return EdmReturnErrCode::PARAM_ERROR;
                }
            }
            return ERR_OK;
    };
    AddonMethodSign addonMethodSign;
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::CUSTOM};
    addonMethodSign.argsConvert = {nullptr, convertUsbDeviceIds2Data};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.name = (isAdd ? "addAllowedUsbDevices" : "removeAllowedUsbDevices");
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }
    auto usbManagerProxy = UsbManagerProxy::GetUsbManagerProxy();
    if (usbManagerProxy == nullptr) {
        EDMLOGE("can not get usbManagerProxy");
        return nullptr;
    }
    int32_t ret = ERR_OK;
    if (isAdd) {
        ret = usbManagerProxy->AddAllowedUsbDevices(adapterAddonData.data);
    } else {
        ret = usbManagerProxy->RemoveAllowedUsbDevices(adapterAddonData.data);
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
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "getAllowedUsbDevices";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT_NULL};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }

    auto usbManagerProxy = UsbManagerProxy::GetUsbManagerProxy();
    if (usbManagerProxy == nullptr) {
        EDMLOGE("can not get usbManagerProxy");
        return nullptr;
    }
    std::vector<UsbDeviceId> usbDeviceIds;
    int32_t ret = usbManagerProxy->GetAllowedUsbDevices(adapterAddonData.data, usbDeviceIds);
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
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "setUsbStorageDeviceAccessPolicy";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::INT32};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }

    auto usbManagerProxy = UsbManagerProxy::GetUsbManagerProxy();
    if (usbManagerProxy == nullptr) {
        EDMLOGE("can not get usbManagerProxy");
        return nullptr;
    }
    int32_t ret = usbManagerProxy->SetUsbStorageDeviceAccessPolicy(adapterAddonData.data);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value UsbManagerAddon::GetUsbStorageDeviceAccessPolicy(napi_env env, napi_callback_info info)
{
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "getUsbStorageDeviceAccessPolicy";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT_NULL};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }

    int32_t usbPolicy = EdmConstants::STORAGE_USB_POLICY_READ_WRITE;
    auto usbManagerProxy = UsbManagerProxy::GetUsbManagerProxy();
    if (usbManagerProxy == nullptr) {
        EDMLOGE("can not get usbManagerProxy");
        return nullptr;
    }
    int32_t ret = usbManagerProxy->GetUsbStorageDeviceAccessPolicy(adapterAddonData.data, usbPolicy);
    EDMLOGI("UsbManagerAddon::GetUsbStorageDeviceAccessPolicy return: %{public}d", usbPolicy);
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, usbPolicy, &result));
    return result;
}

napi_value UsbManagerAddon::AddDisallowedUsbDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::AddDisallowedUsbDevices called");
    return AddOrRemoveDisallowedUsbDevices(env, info, true, true);
}

napi_value UsbManagerAddon::RemoveDisallowedUsbDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::RemoveDisallowedUsbDevices called");
    return AddOrRemoveDisallowedUsbDevices(env, info, false, true);
}

napi_value UsbManagerAddon::AddDisallowedPermissiveUsbDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::AddDisallowedPermissiveUsbDevices called");
    return AddOrRemoveDisallowedUsbDevices(env, info, true, false);
}

napi_value UsbManagerAddon::RemoveDisallowedPermissiveUsbDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::RemoveDisallowedPermissiveUsbDevices called");
    return AddOrRemoveDisallowedUsbDevices(env, info, false, false);
}

napi_value UsbManagerAddon::AddOrRemoveDisallowedUsbDevices(napi_env env, napi_callback_info info, bool isAdd,
    bool notPermissive)
{
    auto convertUsbDeviceType2Data = [notPermissive](napi_env env, napi_value argv, MessageParcel &data,
        const AddonMethodSign &methodSign) -> ErrCode {
            std::vector<USB::UsbDeviceType> usbDeviceTypes;
            int32_t ans = ParseUsbDeviceTypesArray(env, usbDeviceTypes, argv, notPermissive);
            if (FAILED(ans)) { // LCOV_EXCL_BR_LINE
                EDMLOGE("parameter type parse error");
                if (notPermissive && ans == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED) {
                    ans = EdmReturnErrCode::PARAM_ERROR;
                }
                return ans;
            }
            auto size = usbDeviceTypes.size();
            if (size > (notPermissive ? EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE :
            EdmConstants::DISALLOWED_PERMISSIVE_USB_DEVICES_TYPES_MAX_SIZE)) {
                EDMLOGE("UsbManagerProxy:AddOrRemoveDisallowedUsbDevices size=[%{public}zu] is too large", size);
                return notPermissive ? EdmReturnErrCode::PARAM_ERROR : EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
            }
            data.WriteUint32(size);
            for (const auto &usbDeviceType : usbDeviceTypes) {
                if (!usbDeviceType.Marshalling(data)) {
                    EDMLOGE("UsbManagerProxy AddOrRemoveDisallowedUsbDevices: write parcel failed!");
                    return EdmReturnErrCode::PARAM_ERROR;
                }
            }
            return ERR_OK;
    };
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = (isAdd ? "addDisallowedUsbDevices" : "removeDisallowedUsbDevices");
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::CUSTOM};
    addonMethodSign.argsConvert = {nullptr, convertUsbDeviceType2Data};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.errcodeType = notPermissive ? ErrcodeType::STRING : ErrcodeType::NUMBER;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }

    auto usbManagerProxy = UsbManagerProxy::GetUsbManagerProxy();
    if (usbManagerProxy == nullptr) {
        EDMLOGE("can not get usbManagerProxy");
        return nullptr;
    }
    int32_t ret = usbManagerProxy->AddOrRemoveDisallowedUsbDevices(adapterAddonData.data, isAdd, notPermissive);
    if (FAILED(ret)) {
        if (notPermissive && ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED) {
            ret = EdmReturnErrCode::PARAM_ERROR;
        }
        napi_throw(env, CreateError(env, ret));
    }
    return nullptr;
}

napi_value UsbManagerAddon::GetDisallowedUsbDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::GetDisallowedUsbDevices called");
    return GetDisallowedUsbDevicesCore(env, info, true);
}

napi_value UsbManagerAddon::GetDisallowedPermissiveUsbDevices(napi_env env, napi_callback_info info)
{
    EDMLOGI("UsbManagerAddon::GetDisallowedPermissiveUsbDevices called");
    return GetDisallowedUsbDevicesCore(env, info, false);
}

napi_value UsbManagerAddon::GetDisallowedUsbDevicesCore(napi_env env, napi_callback_info info, bool notPermissive)
{
    EDMLOGI("UsbManagerAddon::GetDisallowedUsbDevicesCore called");
    AddonMethodSign addonMethodSign;
    addonMethodSign.name = "getDisallowedUsbDevices";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT_NULL};
    addonMethodSign.methodAttribute = MethodAttribute::GET;
    addonMethodSign.errcodeType = notPermissive ? ErrcodeType::STRING : ErrcodeType::NUMBER;
    AdapterAddonData adapterAddonData{};
    napi_value result = JsObjectToData(env, info, addonMethodSign, &adapterAddonData);
    if (result == nullptr) {
        return nullptr;
    }

    auto usbManagerProxy = UsbManagerProxy::GetUsbManagerProxy();
    if (usbManagerProxy == nullptr) {
        EDMLOGE("can not get usbManagerProxy");
        return nullptr;
    }
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    int32_t ret = usbManagerProxy->GetDisallowedUsbDevices(adapterAddonData.data, usbDeviceTypes, notPermissive);
    EDMLOGI("UsbManagerAddon::GetDisallowedUsbDevices usbDeviceTypes return size: %{public}zu", usbDeviceTypes.size());
    if (FAILED(ret)) {
        napi_throw(env, CreateError(env, ret));
        return nullptr;
    }
    napi_value jsList = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, usbDeviceTypes.size(), &jsList));
    for (size_t i = 0; i < usbDeviceTypes.size(); i++) {
        napi_value item = UsbDeviceTypeToJsObj(env, usbDeviceTypes[i]);
        NAPI_CALL(env, napi_set_element(env, jsList, i, item));
    }
    return jsList;
}

#ifdef USB_EDM_ENABLE
int32_t UsbManagerAddon::ParseUsbDeviceTypesArray(napi_env env, std::vector<USB::UsbDeviceType> &usbDeviceTypes,
    napi_value object, bool notPermissive)
{
    bool isArray = false;
    napi_is_array(env, object, &isArray);
    if (!isArray) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    uint32_t arrayLength = 0;
    napi_get_array_length(env, object, &arrayLength);
    if (arrayLength > (notPermissive ? EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE :
    EdmConstants::DISALLOWED_PERMISSIVE_USB_DEVICES_TYPES_MAX_SIZE)) {
        EDMLOGE("ParseUsbDeviceTypesArray: arrayLength=[%{public}u] is too large", arrayLength);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    for (uint32_t i = 0; i < arrayLength; i++) {
        napi_value value = nullptr;
        napi_get_element(env, object, i, &value);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if (valueType != napi_object) {
            usbDeviceTypes.clear();
            return EdmReturnErrCode::PARAM_ERROR;
        }
        USB::UsbDeviceType usbDeviceType;
        if (!GetUsbDeviceTypeFromNAPI(env, value, usbDeviceType, notPermissive)) { // LCOV_EXCL_BR_LINE
            usbDeviceTypes.clear();
            return EdmReturnErrCode::PARAM_ERROR;
        }
        usbDeviceTypes.push_back(usbDeviceType);
    }
    return ERR_OK;
}

bool UsbManagerAddon::GetUsbDeviceTypeFromNAPI(napi_env env, napi_value value, USB::UsbDeviceType &usbDeviceType,
    bool notPermissive)
{
    int32_t baseClass = 0;
    if (!JsObjectToInt(env, value, "baseClass", true, baseClass)) {
        EDMLOGE("GetUsbDeviceTypeFromNAPI baseClass parse error!");
        return false;
    }
    int32_t subClass = -1;
    if (!JsObjectToInt(env, value, "subClass", notPermissive, subClass)) { // LCOV_EXCL_BR_LINE
        EDMLOGE("GetUsbDeviceTypeFromNAPI subClass parse error!");
        return false;
    }
    int32_t protocol = -1;
    if (!JsObjectToInt(env, value, "protocol", notPermissive, protocol)) { // LCOV_EXCL_BR_LINE
        EDMLOGE("GetUsbDeviceTypeFromNAPI protocol parse error!");
        return false;
    }
    int32_t descriptor = -1;
    if (!JsObjectToInt(env, value, "descriptor", notPermissive, descriptor)) { // LCOV_EXCL_BR_LINE
        EDMLOGE("GetUsbDeviceTypeFromNAPI descriptor parse error!");
        return false;
    }
    if (descriptor != -1) { // LCOV_EXCL_BR_LINE
        if (!std::any_of(std::begin(DESCRIPTOR), std::end(DESCRIPTOR),
            [&](int item) { return item == descriptor; })) { // LCOV_EXCL_BR_LINE
            EDMLOGE("GetUsbDeviceTypeFromNAPI descriptor value error!");
            return false;
        }
    }
    usbDeviceType.baseClass = baseClass;
    usbDeviceType.subClass = subClass;
    usbDeviceType.protocol = protocol;
    usbDeviceType.isDeviceType = (descriptor == -1) ? false : descriptor;
    usbDeviceType.isDeviceTypeAllMatch = (descriptor == -1) ? true : false;
    EDMLOGD("GetUsbDeviceTypeFromNAPI baseClass: %{public}d, subClass: %{public}d, protocol: %{public}d, "
        "isDeviceType: %{public}d, isDeviceTypeAllMatch: %{public}d",
        baseClass, subClass, protocol, usbDeviceType.isDeviceType, usbDeviceType.isDeviceTypeAllMatch);
    return true;
}

napi_value UsbManagerAddon::UsbDeviceTypeToJsObj(napi_env env, const USB::UsbDeviceType &usbDeviceType)
{
    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value baseClass = nullptr;
    NAPI_CALL(env, napi_create_int32(env, usbDeviceType.baseClass, &baseClass));
    NAPI_CALL(env, napi_set_named_property(env, value, "baseClass", baseClass));

    if (usbDeviceType.subClass != -1) { // LCOV_EXCL_BR_LINE
        napi_value subClass = nullptr;
        NAPI_CALL(env, napi_create_int32(env, usbDeviceType.subClass, &subClass));
        NAPI_CALL(env, napi_set_named_property(env, value, "subClass", subClass));
    }

    if (usbDeviceType.protocol != -1) { // LCOV_EXCL_BR_LINE
        napi_value protocol = nullptr;
        NAPI_CALL(env, napi_create_int32(env, usbDeviceType.protocol, &protocol));
        NAPI_CALL(env, napi_set_named_property(env, value, "protocol", protocol));
    }

    if (!usbDeviceType.isDeviceTypeAllMatch) { // LCOV_EXCL_BR_LINE
        napi_value descriptor = nullptr;
        NAPI_CALL(env, napi_create_int32(env, usbDeviceType.isDeviceType, &descriptor));
        NAPI_CALL(env, napi_set_named_property(env, value, "descriptor", descriptor));
    }
    return value;
}
#endif

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