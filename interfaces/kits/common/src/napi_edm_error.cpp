/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
};

napi_value CreateError(napi_env env, ErrCode errorCode)
{
    auto pair = GetMessageFromReturncode(errorCode);
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

std::pair<int32_t, std::string> GetMessageFromReturncode(ErrCode returnCode)
{
    auto iter = errMessageMap.find(returnCode);
    if (iter != errMessageMap.end()) {
        return std::make_pair(returnCode, iter->second);
    } else {
        return std::make_pair(EdmReturnErrCode::PARAM_ERROR, "some thing wrong happend");
    }
}
} // namespace EDM
} // namespace OHOS