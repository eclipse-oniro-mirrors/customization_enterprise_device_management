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
    {
        EdmReturnErrCode::PERMISSION_DENIED, "the application does not have permission to call this function."
    },
    {
        EdmReturnErrCode::SYSTEM_ABNORMALLY, "the system ability work abnormally."
    },
    {
        EdmReturnErrCode::ENABLE_ADMIN_FAILED, "failed to enable the administrator application of the device."
    },
    {
        EdmReturnErrCode::COMPONENT_INVALID, "the administrator ability component is invalid."
    },
    {
        EdmReturnErrCode::ADMIN_INACTIVE, "the application is not a administrator of the device."
    },
    {
        EdmReturnErrCode::DISABLE_ADMIN_FAILED, "failed to disable the administrator application of the device."
    },
    {
        EdmReturnErrCode::UID_INVALID, "the specified user ID is invalid."
    },
    {
        EdmReturnErrCode::INTERFACE_UNSUPPORTED, "the specified interface is not supported."
    },
    {
        EdmReturnErrCode::PARAM_ERROR, "invalid input parameter."
    },
    {
        EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED,
        "the administrator application does not have permission to manage the device."
    },
    {
        EdmReturnErrCode::MANAGED_EVENTS_INVALID, "the specified managed event is is invalid."
    }
};

napi_value CreateError(napi_env env, ErrCode errorCode)
{
    return CreateError(env, GetMessageFromReturncode(errorCode).first,
        GetMessageFromReturncode(errorCode).second);
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