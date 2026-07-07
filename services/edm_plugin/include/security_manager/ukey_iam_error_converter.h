/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef EDM_PLUGIN_INCLUDE_SECURITY_MANAGER_UKEY_IAM_ERROR_CONVERTER_H
#define EDM_PLUGIN_INCLUDE_SECURITY_MANAGER_UKEY_IAM_ERROR_CONVERTER_H

#include <string>
#include "edm_errors.h"

namespace OHOS {
namespace EDM {

// Account IAM error codes from iam_common_defines.h and account_error_no.h
// Layer 3: IAMResultCode (user_auth/UserIdm)
constexpr int32_t UKEY_ERR_IAM_FAIL = 1;
constexpr int32_t UKEY_ERR_IAM_GENERAL_ERROR = 2;
constexpr int32_t UKEY_ERR_IAM_CANCELED = 3;
constexpr int32_t UKEY_ERR_IAM_TIMEOUT = 4;
constexpr int32_t UKEY_ERR_IAM_TYPE_NOT_SUPPORT = 5;
constexpr int32_t UKEY_ERR_IAM_TRUST_LEVEL_NOT_SUPPORT = 6;
constexpr int32_t UKEY_ERR_IAM_BUSY = 7;
constexpr int32_t UKEY_ERR_IAM_INVALID_PARAMETERS = 8;
constexpr int32_t UKEY_ERR_IAM_LOCKED = 9;
constexpr int32_t UKEY_ERR_IAM_NOT_ENROLLED = 10;
constexpr int32_t UKEY_ERR_IAM_CANCELED_FROM_WIDGET = 11;
constexpr int32_t UKEY_ERR_IAM_HARDWARE_NOT_SUPPORTED = 12;
constexpr int32_t UKEY_ERR_IAM_PIN_EXPIRED = 13;
constexpr int32_t UKEY_ERR_IAM_COMPLEXITY_CHECK_FAILED = 14;
constexpr int32_t UKEY_ERR_IAM_AUTH_TOKEN_CHECK_FAILED = 15;
constexpr int32_t UKEY_ERR_IAM_AUTH_TOKEN_EXPIRED = 16;
constexpr int32_t UKEY_ERR_IAM_REUSE_AUTH_RESULT_FAILED = 17;
constexpr int32_t UKEY_ERR_IAM_NO_VALID_CREDENTIAL = 18;
constexpr int32_t UKEY_ERR_IAM_IPC_ERROR = 1001;
constexpr int32_t UKEY_ERR_IAM_INVALID_CONTEXT_ID = 1002;
constexpr int32_t UKEY_ERR_IAM_READ_PARCEL_ERROR = 1003;
constexpr int32_t UKEY_ERR_IAM_WRITE_PARCEL_ERROR = 1004;
constexpr int32_t UKEY_ERR_IAM_CHECK_PERMISSION_FAILED = 1005;
constexpr int32_t UKEY_ERR_IAM_INVALID_HDI_INTERFACE = 1006;
constexpr int32_t UKEY_ERR_IAM_CHECK_SYSTEM_APP_FAILED = 1007;
constexpr int32_t UKEY_ERR_IAM_CROSS_DEVICE_COMMUNICATION_FAILED = 1008;
constexpr int32_t UKEY_ERR_IAM_CROSS_DEVICE_CAPABILITY_NOT_SUPPORT = 1009;
constexpr int32_t UKEY_ERR_IAM_TOKEN_TIMEOUT = 10016;
constexpr int32_t UKEY_ERR_IAM_TOKEN_AUTH_FAILED = 10017;
constexpr int32_t UKEY_ERR_IAM_CREDENTIAL_NUMBER_REACH_LIMIT = 10018;
constexpr int32_t UKEY_ERR_IAM_SESSION_TIMEOUT = 10019;

// Layer 1: Account Common (4194304+)
constexpr int32_t UKEY_ERR_ACCOUNT_COMMON_INVALID_PARAMETER = 4194331;
constexpr int32_t UKEY_ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR = 4194332;
constexpr int32_t UKEY_ERR_ACCOUNT_COMMON_REMOTE_DIED = 4194356;
constexpr int32_t UKEY_ERR_ACCOUNT_COMMON_BUSY = 4194357;
constexpr int32_t UKEY_ERR_ACCOUNT_COMMON_OPERATION_FAIL = 4194370;

/**
 * @brief Converts Account IAM error code to EDM error code with detailed message.
 *
 * Category 1 (User input) -> PARAMETER_VERIFICATION_FAILED (9200012)
 * Category 2 (Timeout)    -> EDM_ERR_UKEY_TIMEOUT (9201050)
 * Category 3 (Service)    -> EXECUTE_TIME_OUT (9200016)
 *
 * @param iamRet The error code returned by AccountIAMClient.
 * @param errMsg Output parameter for the detailed error message.
 * @return The converted EDM error code.
 */
ErrCode ConvertIamError(int32_t iamRet, std::string &errMsg);

} // namespace EDM
} // namespace OHOS

#endif // EDM_PLUGIN_INCLUDE_SECURITY_MANAGER_UKEY_IAM_ERROR_CONVERTER_H
