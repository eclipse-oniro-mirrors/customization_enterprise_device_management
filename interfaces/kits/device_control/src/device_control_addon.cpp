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

#include <fcntl.h>
#include <fstream>

#include "device_control_addon.h"
#include "edm_constants.h"
#include "operate_device_param.h"
#ifdef OS_ACCOUNT_EDM_ENABLE
#include "os_account_manager.h"
#endif
#include "edm_log.h"

using namespace OHOS::EDM;

napi_value DeviceControlAddon::Init(napi_env env, napi_value exports)
{
    napi_value nOperation = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nOperation));
    CreateOperationObject(env, nOperation);
    napi_property_descriptor property[] = {
        DECLARE_NAPI_FUNCTION("resetFactory", ResetFactory),
        DECLARE_NAPI_FUNCTION("shutdown", Shutdown),
        DECLARE_NAPI_FUNCTION("reboot", Reboot),
        DECLARE_NAPI_FUNCTION("lockScreen", LockScreen),
        DECLARE_NAPI_FUNCTION("operateDevice", OperateDevice),
        DECLARE_NAPI_PROPERTY("Operation", nOperation),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(property) / sizeof(property[0]), property));
    return exports;
}

void DeviceControlAddon::CreateOperationObject(napi_env env, napi_value value)
{
    napi_value nDiskErase;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(EdmConstants::DeviceControl::OperateType::DISK_ERASURE), &nDiskErase));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "DISK_ERASURE", nDiskErase));
    napi_value nResetFactory;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(EdmConstants::DeviceControl::OperateType::RESET_FACTORY), &nResetFactory));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "RESET_FACTORY", nResetFactory));
    napi_value nReboot;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(EdmConstants::DeviceControl::OperateType::REBOOT), &nReboot));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "REBOOT", nReboot));
    napi_value nShutDown;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(EdmConstants::DeviceControl::OperateType::SHUT_DOWN), &nShutDown));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SHUT_DOWN", nShutDown));
    napi_value nLockScreen;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(EdmConstants::DeviceControl::OperateType::LOCK_SCREEN), &nLockScreen));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "LOCK_SCREEN", nLockScreen));
    napi_value nLockDevice;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(EdmConstants::DeviceControl::OperateType::LOCK_DEVICE), &nLockDevice));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "LOCK_DEVICE", nLockDevice));
    napi_value nUnlockDevice;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        static_cast<int32_t>(EdmConstants::DeviceControl::OperateType::UNLOCK_DEVICE), &nUnlockDevice));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "UNLOCK_DEVICE", nUnlockDevice));
}

void DeviceControlAddon::SetPolicyCommon(AddonMethodSign &addonMethodSign, const std::string &workName)
{
    addonMethodSign.name = workName;
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
}

napi_value DeviceControlAddon::ResetFactory(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_resetFactory called");
    AddonMethodSign addonMethodSign;
    SetPolicyCommon(addonMethodSign, "ResetFactory");
    return AddonMethodAdapter(env, info, addonMethodSign, NativeResetFactory, NativeVoidCallbackComplete);
}

napi_value DeviceControlAddon::LockScreen(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_lockScreen called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_ONE, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    ASSERT_AND_THROW_PARAM_ERROR(env, matchFlag, "parameter type error");
    OHOS::AppExecFwk::ElementName elementName;
    bool ret = ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]);
    ASSERT_AND_THROW_PARAM_ERROR(env, ret, "element name param error");
    EDMLOGD("lockScreen: asyncCallbackInfo->elementName.bundlename %{public}s, "
        "asyncCallbackInfo->abilityname:%{public}s",
        elementName.GetBundleName().c_str(),
        elementName.GetAbilityName().c_str());
    int32_t userId = 0;
#ifdef OS_ACCOUNT_EDM_ENABLE
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    EDMLOGI("NAPI_lockScreen called userId");
#else
    EDMLOGI("NAPI_lockScreen don't call userId");
#endif
    int32_t result = DeviceControlProxy::GetDeviceControlProxy()->LockScreen(elementName, userId);
    if (FAILED(result)) {
        napi_throw(env, CreateError(env, result));
    }
    return nullptr;
}

napi_value DeviceControlAddon::Shutdown(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_shutdown called");
    AddonMethodSign addonMethodSign;
    SetPolicyCommon(addonMethodSign, "Shutdown");
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    int32_t result = DeviceControlProxy::GetDeviceControlProxy()->Shutdown(adapterAddonData.data);
    if (FAILED(result)) {
        napi_throw(env, CreateError(env, result));
    }
    return nullptr;
}

napi_value DeviceControlAddon::Reboot(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_reboot called");
    AddonMethodSign addonMethodSign;
    SetPolicyCommon(addonMethodSign, "Reboot");
    AdapterAddonData adapterAddonData{};
    if (JsObjectToData(env, info, addonMethodSign, &adapterAddonData) == nullptr) {
        return nullptr;
    }
    int32_t result = DeviceControlProxy::GetDeviceControlProxy()->Reboot(adapterAddonData.data);
    if (FAILED(result)) {
        napi_throw(env, CreateError(env, result));
    }
    return nullptr;
}

void DeviceControlAddon::NativeResetFactory(napi_env env, void *data)
{
    EDMLOGI("NAPI_NativeResetFactory called");
    if (data == nullptr) {
        EDMLOGE("data is nullptr");
        return;
    }
    AdapterAddonData *asyncCallbackInfo = static_cast<AdapterAddonData *>(data);
    if (DeviceControlProxy::GetDeviceControlProxy() == nullptr) {
        EDMLOGE("can not get GetDeviceControlProxy");
        return;
    }
    asyncCallbackInfo->ret =
        DeviceControlProxy::GetDeviceControlProxy()->ResetFactory(asyncCallbackInfo->data);
}

bool DeviceControlAddon::ReadFileToBytes(const std::string fileName, int32_t &fileSize, std::vector<uint8_t> &res)
{
    char canonicalPath[PATH_MAX + 1] = { 0 };
    if (fileName.size() > PATH_MAX || realpath(fileName.c_str(), canonicalPath) == nullptr) {
        EDMLOGE("realpath error");
        return false;
    }
    std::string realPath(canonicalPath);
    std::ifstream file(realPath, std::ios::binary);
    if (!file) {
        EDMLOGE("can not open file");
        return false;
    }
 
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    if (size < 0 || size > EdmConstants::MAX_DISK_ERASE_IMAGE_SIZE) {
        EDMLOGE("file size is abnormally");
        return false;
    }
 
    std::vector<uint8_t> buffer(size);
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        EDMLOGI("success to read file");
        fileSize = size;
        res = buffer;
        return true;
    }
    EDMLOGE("failed to read file");
    return false;
}

napi_value DeviceControlAddon::OperateDevice(napi_env env, napi_callback_info info)
{
    EDMLOGI("NAPI_OperateDevice called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    ASSERT_AND_THROW_PARAM_ERROR(env, argc >= ARGS_SIZE_TWO, "parameter count error");
    bool matchFlag = MatchValueType(env, argv[ARR_INDEX_ZERO], napi_object);
    napi_valuetype operateType = napi_undefined;
    napi_typeof(env, argv[ARR_INDEX_ONE], &operateType);
    if (operateType != napi_string && operateType != napi_number) {
        matchFlag = false;
    }
    if (argc > ARGS_SIZE_TWO) {
        matchFlag = matchFlag && MatchValueType(env, argv[ARR_INDEX_TWO], napi_string);
    }
    ErrcodeType errcodeType = (operateType == napi_number) ? ErrcodeType::NUMBER : ErrcodeType::STRING;
    ASSERT_AND_THROW_PARAM_ERROR_BY_TYPE(env, matchFlag, "parameter type error", errcodeType);
    AppExecFwk::ElementName elementName;
    ASSERT_AND_THROW_PARAM_ERROR_BY_TYPE(
        env, ParseElementName(env, elementName, argv[ARR_INDEX_ZERO]), "element name param error", errcodeType);
    OperateDeviceParam param;
    if (!ConvertOperation(env, operateType, param, argv[ARR_INDEX_ONE])) {
        return nullptr;
    }
    if (argc > ARGS_SIZE_TWO) {
        ASSERT_AND_THROW_PARAM_ERROR_BY_TYPE(env, ParseString(env, param.addition, argv[ARR_INDEX_TWO]),
            "addition param error", errcodeType);
        if (param.operate == EdmConstants::DeviceControl::DISK_ERASE) {
            if (!param.addition.empty() && !ReadFileToBytes(param.addition, param.size, param.file)) {
                napi_throw(env,
                    CreateError(env, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED, ErrcodeType::NUMBER));
                return nullptr;
            }
        }
    }
#ifdef OS_ACCOUNT_EDM_ENABLE
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(param.userId);
    EDMLOGI("NAPI_OperateDevice called userId");
#else
    EDMLOGI("NAPI_OperateDevice don't call userId");
#endif
    int32_t ret = DeviceControlProxy::GetDeviceControlProxy()->OperateDevice(elementName, param);
    if (FAILED(ret)) {
        ThrowOperateDeviceError(env, ret, errcodeType);
    }
    return nullptr;
}

void DeviceControlAddon::ThrowOperateDeviceError(napi_env env, int32_t ret, ErrcodeType errcodeType)
{
    if (errcodeType == ErrcodeType::NUMBER) {
        if (ret == EdmReturnErrCode::PARAM_ERROR || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY) {
            napi_throw(env,
                CreateError(env, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED, ErrcodeType::NUMBER));
        } else {
            napi_throw(env, CreateError(env, ret, errcodeType));
        }
    } else {
        napi_throw(env, CreateError(env, ret));
    }
}

bool DeviceControlAddon::ConvertOperation(napi_env env, napi_valuetype operateType, OperateDeviceParam &param,
    napi_value value)
{
    if (operateType == napi_string) {
        ASSERT_AND_THROW_PARAM_ERROR(env, ParseString(env, param.operate, value),
            "operate param error");
        if (param.operate == "diskErase") {
            EDMLOGE("OperateDevice invalid operate string: %{public}s", param.operate.c_str());
            napi_throw(env, CreateError(env, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED, ErrcodeType::NUMBER));
            return false;
        }
    } else if (operateType == napi_number) {
        int32_t operateValue = 0;
        ASSERT_AND_THROW_PARAM_ERROR_BY_TYPE(env, ParseInt(env, operateValue, value),
            "operate param error", ErrcodeType::NUMBER);
        param.operate = ConvertOperateTypeToString(static_cast<EdmConstants::DeviceControl::OperateType>(operateValue));
        if (param.operate.empty()) {
            EDMLOGE("OperateDevice invalid operate enum value: %{public}d", operateValue);
            napi_throw(env, CreateError(env, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED, ErrcodeType::NUMBER));
            return false;
        }
    }
    return true;
}

std::string DeviceControlAddon::ConvertOperateTypeToString(EdmConstants::DeviceControl::OperateType operateType)
{
    switch (operateType) {
        case EdmConstants::DeviceControl::OperateType::DISK_ERASURE:
            return EdmConstants::DeviceControl::DISK_ERASE;
        case EdmConstants::DeviceControl::OperateType::RESET_FACTORY:
            return EdmConstants::DeviceControl::RESET_FACTORY;
        case EdmConstants::DeviceControl::OperateType::REBOOT:
            return EdmConstants::DeviceControl::REBOOT;
        case EdmConstants::DeviceControl::OperateType::SHUT_DOWN:
            return EdmConstants::DeviceControl::SHUT_DOWN;
        case EdmConstants::DeviceControl::OperateType::LOCK_SCREEN:
            return EdmConstants::DeviceControl::LOCK_SCREEN;
        case EdmConstants::DeviceControl::OperateType::LOCK_DEVICE:
            return EdmConstants::DeviceControl::LOCK_DEVICE;
        case EdmConstants::DeviceControl::OperateType::UNLOCK_DEVICE:
            return EdmConstants::DeviceControl::UNLOCK_DEVICE;
        default:
            return "";
    }
}

static napi_module g_deviceControlModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = DeviceControlAddon::Init,
    .nm_modname = "enterprise.deviceControl",
    .nm_priv = ((void *)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void DeviceControlManagerRegister()
{
    napi_module_register(&g_deviceControlModule);
}
