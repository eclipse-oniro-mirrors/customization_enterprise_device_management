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

#include "napi_edm_error.h"

#include <unordered_map>

namespace OHOS {
namespace EDM {
static const std::unordered_map<int32_t, std::string> errMessageMap = {
    {EdmReturnErrCode::PERMISSION_DENIED,
        "Permission verification failed. The application does not have the permission required to call the API."},
    {EdmReturnErrCode::SYSTEM_ABNORMALLY, "The system ability works abnormally."},
    {EdmReturnErrCode::ENABLE_ADMIN_FAILED, "Failed to activate the administrator application of the device."},
    {EdmReturnErrCode::COMPONENT_INVALID, "The administrator ability component is invalid."},
    {EdmReturnErrCode::ADMIN_INACTIVE, "The application is not an administrator application of the device."},
    {EdmReturnErrCode::DISABLE_ADMIN_FAILED, "Failed to deactivate the administrator application of the device."},
    {EdmReturnErrCode::UID_INVALID, "The specified user ID is invalid."},
    {EdmReturnErrCode::INTERFACE_UNSUPPORTED,
        "Capability not supported. Failed to call the API due to limited device capabilities."},
    {EdmReturnErrCode::PARAM_ERROR, "Parameter error."},
    {EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED,
        "The administrator application does not have permission to manage the device."},
    {EdmReturnErrCode::MANAGED_EVENTS_INVALID, "The specified system event is invalid."},
    {EdmReturnErrCode::SYSTEM_API_DENIED,
        "Permission verification failed. A non-system application calls a system API."},
    {EdmReturnErrCode::MANAGED_CERTIFICATE_FAILED, "Failed to manage the certificate. $."},
    {EdmReturnErrCode::AUTHORIZE_PERMISSION_FAILED, "Failed to grant the permission to the application."},
    {EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED, "A conflict policy has been configured."},
    {EdmReturnErrCode::APPLICATION_INSTALL_FAILED, "Failed to install the application. $."},
    {EdmReturnErrCode::ADD_OS_ACCOUNT_FAILED, "Failed to add an OS account."},
    {EdmReturnErrCode::UPGRADE_PACKAGES_ANALYZE_FAILED, "the upgrade packages do not exist or analyzing failed, $."},
    {EdmReturnErrCode::ADD_KEEP_ALIVE_APP_FAILED, "Add keep alive applications failed. $."},
    {EdmReturnErrCode::CERTIFICATE_REACHED_LIMIT, "The number of certificates has reached the limit."},
    {EdmReturnErrCode::CERTIFICATE_IS_INVALID, "The certificate is invalid."},
    {EdmReturnErrCode::CERTIFICATE_NOT_EXIST, "The certificate does not exist."},
    {EdmReturnErrCode::REPLACE_ADMIN_FAILED, "Replace admin failed. $."},
    {EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED, "parameter verification failed. $"},
    {EdmReturnErrCode::ENTERPRISE_POLICES_DENIED, "This function is prohibited by enterprise management policies."},
    {EdmReturnErrCode::DISALLOW_NOT_TAKE_EFFECT,
        "The enterprise management policy has been successfully set, " \
        "but the function has not taken effect in real time."},
    {EdmReturnErrCode::ETHERNET_CONFIGURATION_FAILED, "Ethernet configuration failed."},
    {EdmReturnErrCode::START_ABILITY_FAILED, "Failed to start the ability. $"},
    {EdmReturnErrCode::ABILITY_NOT_EXIST, "The ability does not exist."},
    {EdmReturnErrCode::FAULTLOG_COLLECT_FAILED, "Collecting logs, please try again later."},
    {EdmReturnErrCode::EXECUTE_TIME_OUT, "Service timeout."},
    {EdmReturnErrCode::INVALID_ACTIVATION_LOCK_CREDENTIALS, "The credential of the activation lock is invalid."},
    {EdmReturnErrCode::ENABLE_ACTIVATION_LOCK_FAILED, "Failed to enable or disable the activation lock."},
    {EdmReturnErrCode::ACTIVE_SIM_FAILED, "Failed to active sim, please turn off airplane mode or insert sim card."},
    {EdmReturnErrCode::DOCK_APP_IS_OVER_MAX, "The number of applications in the Dock has reached the maximum."},
    {EdmReturnErrCode::DOCK_APP_IS_ALREADY_IN_DOCK, "The application is already in the Dock."},
    {EdmReturnErrCode::DOCK_APP_NOT_INSTALLED, "The application is not installed."},
    {EdmReturnErrCode::DOCK_APP_NOT_IN_DOCK, "The application has not been added to the Dock."},
    {EdmReturnErrCode::DOCK_APP_BUNDLE_NOT_SUPPORT, "The application is inoperable"},
    {EdmReturnErrCode::DOCK_APP_INDEX_NOT_SUPPORT, "The location is inoperable"},
    {EdmReturnErrCode::SET_DEFAULT_DATA_SIM_FAILED,
        "Failed to set default data sim, please turn off airplane mode or insert sim card."},
    {EdmReturnErrCode::SCREEN_LOCK_PWD_HAS_BEEN_SET,
        "A lock screen password has been set for the device."},
    {EdmReturnErrCode::SWITCH_STATUS_FAILED, "switch status failed."},
    {EdmReturnErrCode::CHECK_CREDENTIAL_FAILED, "check credential info fialed, please check the credential."},
    {EdmReturnErrCode::NOT_ENTERPRISE_DEVICE, "current device is not enterprise device or not offline activation."},
    {EdmReturnErrCode::INSTALL_APP_INSUFFICIENT_DISK_SPACE,
        "Failed to install the HAP because of insufficient system disk space."},
    {EdmReturnErrCode::INSTALL_APP_ENTERPRISE_DISALLOWED,
        "Failed to install the HAP because enterprise device management disallows the installation."},
    {EdmReturnErrCode::INSTALL_APP_PARSE_FAILED, "Failed to install the HAP because the HAP fails to be parsed."},
    {EdmReturnErrCode::INSTALL_APP_SIGNATURE_VERIFY_FAILED,
        "Failed to install the HAP because the HAP signature fails to be verified."},
    {EdmReturnErrCode::INSTALL_APP_PATH_INVALID_OR_TOO_LARGE,
        "Failed to install the HAP because the HAP path is invalid or the HAP is too large."},
    {EdmReturnErrCode::INSTALL_APPS_CONFIGURATION_MISMATCH,
        "Failed to install the HAPs because they have different configuration information."},
    {EdmReturnErrCode::INSTALL_APP_ISOLATION_MODE_NOT_SUPPORTED,
        "Failed to install the HAP because the isolationMode configured is not supported."},
    {EdmReturnErrCode::INSTALL_APP_VERSION_TOO_EARLY,
        "Failed to install the HAP since the version of the HAP to install is too early."},
    {EdmReturnErrCode::INSTALL_APP_VERSION_CODE_NOT_GREATER,
        "Failed to install the HAP because the VersionCode to be updated is not greater than the current VersionCode."},
    {EdmReturnErrCode::INSTALL_APP_DEPENDANT_MODULE_NOT_EXIST,
        "Installation failed because the dependant module does not exist."},
    {EdmReturnErrCode::INSTALL_APP_USER_ID_NOT_FOUND, "The specified user ID is not found."},
    {EdmReturnErrCode::INSTALL_APP_OVERLAY_CHECK_FAILED, "Failed to install the HAP because the overlay check failed."},
    {EdmReturnErrCode::INSTALL_APP_MISSING_REQUIRED_PERMISSIONS_FOR_HSP,
        "Failed to install the HSP due to missing required permissions."},
    {EdmReturnErrCode::INSTALL_APP_SHARED_LIBRARIES_NOT_ALLOWED,
        "Installation failed because the installation of cross-app shared libraries is not allowed."},
    {EdmReturnErrCode::INSTALL_APP_URI_INCORRECT, "Failed to install the HAP due to incorrect URI in the data proxy."},
    {EdmReturnErrCode::INSTALL_APP_PERMISSION_CONFIGURATION_INCORRECT,
        "Failed to install the HAP due to incorrect permission configuration in the data proxy."},
    {EdmReturnErrCode::INSTALL_APP_CODE_SIGNATURE_VERIFICATION_FAILURE,
        "Failed to install the HAP due to code signature verification failure."},
    {EdmReturnErrCode::INSTALL_APP_ENTERPRISE_DEVICE_VERIFICATION_FAILURE,
        "Failed to install the HAP due to enterprise device verification failure."},
    {EdmReturnErrCode::PREREQUISITES_NOT_SATISFIED_FAILED,
        "Prerequisites for the API call have not been satisfied. For example, distributed outgoing transmission " \
        "is not disallowed before adding the distributed bidirectional collaboration trustlist."},
};

napi_value CreateError(napi_env env, ErrCode errorCode, ErrcodeType errcodeType)
{
    auto pair = GetMessageFromReturncode(errorCode);
    if (errcodeType == ErrcodeType::STRING) {
        return CreateError(env, pair.first, pair.second);
    } else {
        return CreateErrorAfterApi24(env, pair.first, pair.second);
    }
}

napi_value CreateErrorWithUnknownCode(napi_env env, ErrCode errorCode)
{
    auto pair = GetMessageWithUnknownCodeFromReturncode(errorCode);
    return CreateError(env, pair.first, pair.second);
}

napi_value CreateErrorWithInnerCode(napi_env env, ErrCode errorCode, std::string &errMessage)
{
    auto pair = GetMessageFromReturncode(errorCode);
    auto iter = pair.second.find("$");
    if (iter != std::string::npos) {
        pair.second = pair.second.replace(iter, 1, errMessage);
    }
    return CreateError(env, pair.first, pair.second);
}

napi_value CreateError(napi_env env, int32_t errorCode, const std::string &errMessage)
{
    napi_value result = nullptr;
    napi_value message = nullptr;
    napi_value errorCodeStr = nullptr;
    napi_create_string_utf8(env, static_cast<char *>(std::to_string(errorCode).data()),
        std::to_string(errorCode).size(), &errorCodeStr);
    napi_create_string_utf8(env, errMessage.c_str(), errMessage.size(), &message);
    napi_create_error(env, errorCodeStr, message, &result);
    return result;
}

napi_value CreateErrorAfterApi24(napi_env env, int32_t errorCode, const std::string &errMessage)
{
    napi_value result = nullptr;
    napi_value message = nullptr;
    napi_value errorCodeNum = nullptr;
    napi_create_int32(env, errorCode, &errorCodeNum);
    napi_create_string_utf8(env, errMessage.c_str(), errMessage.size(), &message);
    napi_create_error(env, nullptr, message, &result);
    napi_set_named_property(env, result, "code", errorCodeNum);
    return result;
}

napi_value CreateErrorByType(napi_env env, int32_t errorCode, const std::string &errMessage,
    ErrcodeType errcodeType)
{
    if (errcodeType == ErrcodeType::STRING) {
        return CreateError(env, errorCode, errMessage);
    } else {
        return CreateErrorAfterApi24(env, errorCode, errMessage);
    }
}

std::pair<int32_t, std::string> GetMessageFromReturncode(ErrCode returnCode)
{
    auto iter = errMessageMap.find(returnCode);
    if (iter != errMessageMap.end()) {
        return std::make_pair(returnCode, iter->second);
    } else {
        return std::make_pair(EdmReturnErrCode::PARAM_ERROR, "some thing wrong happend");
    }
}

std::pair<int32_t, std::string> GetMessageWithUnknownCodeFromReturncode(ErrCode returnCode)
{
    auto iter = errMessageMap.find(returnCode);
    if (iter != errMessageMap.end()) {
        return std::make_pair(returnCode, iter->second);
    }
    return std::make_pair(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED, "parameter verification failed.");
}

bool IsEDMErrCode(ErrCode returnCode)
{
    return errMessageMap.find(returnCode) != errMessageMap.end();
}
} // namespace EDM
} // namespace OHOS