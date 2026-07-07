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

#include "ukey_iam_error_converter.h"

namespace OHOS {
namespace EDM {

ErrCode ConvertIamError(int32_t iamRet, std::string &errMsg)
{
    // Category 1: User input errors -> PARAMETER_VERIFICATION_FAILED
    switch (iamRet) {
        case UKEY_ERR_ACCOUNT_COMMON_INVALID_PARAMETER:
            errMsg = "Invalid account ID. The specified account ID is invalid.";
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        case UKEY_ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR:
            errMsg = "Account not found. The specified account does not exist.";
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        case UKEY_ERR_IAM_INVALID_PARAMETERS:
            errMsg = "Invalid parameter. Please check the input parameters.";
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        case UKEY_ERR_IAM_AUTH_TOKEN_CHECK_FAILED:
            errMsg = "Auth token verification failed. The token signature does not match.";
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        case UKEY_ERR_IAM_TOKEN_AUTH_FAILED:
            errMsg = "Token authentication failed. Please verify the token.";
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        case UKEY_ERR_IAM_NOT_ENROLLED:
            errMsg = "Credential not found. The specified credential ID is not enrolled.";
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        case UKEY_ERR_IAM_NO_VALID_CREDENTIAL:
            errMsg = "No valid credential available. Please check the credential status.";
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        case UKEY_ERR_IAM_CREDENTIAL_NUMBER_REACH_LIMIT:
            errMsg = "Credential limit reached. The maximum number of credentials has been reached.";
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        // Category 2: Timeout errors -> EDM_ERR_UKEY_TIMEOUT
        case UKEY_ERR_IAM_SESSION_TIMEOUT:
            errMsg = "Session expired.";
            return EdmReturnErrCode::EDM_ERR_UKEY_TIMEOUT;
        case UKEY_ERR_IAM_TOKEN_TIMEOUT:
        case UKEY_ERR_IAM_AUTH_TOKEN_EXPIRED:
            errMsg = "Auth token expired.";
            return EdmReturnErrCode::EDM_ERR_UKEY_TIMEOUT;
        // Category 3: Service errors -> EXECUTE_TIME_OUT
        case UKEY_ERR_IAM_TIMEOUT:
        case UKEY_ERR_IAM_GENERAL_ERROR:
        case UKEY_ERR_IAM_HARDWARE_NOT_SUPPORTED:
        case UKEY_ERR_IAM_BUSY:
        case UKEY_ERR_IAM_IPC_ERROR:
        case UKEY_ERR_IAM_CHECK_PERMISSION_FAILED:
        case UKEY_ERR_ACCOUNT_COMMON_REMOTE_DIED:
        case UKEY_ERR_ACCOUNT_COMMON_BUSY:
        case UKEY_ERR_ACCOUNT_COMMON_OPERATION_FAIL:
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
        default:
            errMsg = "Unknown UKey error.";
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
}

} // namespace EDM
} // namespace OHOS
