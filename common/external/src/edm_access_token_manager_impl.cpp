/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "edm_access_token_manager_impl.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "parameters.h"
#include "tokenid_kit.h"

#include "edm_log.h"

namespace OHOS {
namespace EDM {
const std::string DEVELOP_MODE_STATE = "const.security.developermode.state";

bool EdmAccessTokenManagerImpl::IsDebug()
{
    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::ATokenTypeEnum tokenType =
        Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL &&
        system::GetBoolParameter(DEVELOP_MODE_STATE, false)) {
        EDMLOGI("EdmAccessTokenManagerImpl::caller tokenType is shell and check developer mode success.");
        return true;
    }
    return false;
}

bool EdmAccessTokenManagerImpl::IsSystemAppOrNative()
{
    bool isSystemApp =
        Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(IPCSkeleton::GetCallingFullTokenID());
    Security::AccessToken::ATokenTypeEnum tokenType =
        Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(IPCSkeleton::GetCallingTokenID());
    if (isSystemApp || tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        EDMLOGE("EdmAccessTokenManagerImpl::not system app or native process");
        return true;
    }
    return false;
}

bool EdmAccessTokenManagerImpl::VerifyCallingPermission(const std::string &permissionName)
{
    EDMLOGD("EdmAccessTokenManagerImpl::VerifyCallingPermission permission %{public}s", permissionName.c_str());
    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        EDMLOGI("EdmAccessTokenManagerImpl::permission %{public}s: PERMISSION_GRANTED", permissionName.c_str());
        return true;
    }
    EDMLOGW("EdmAccessTokenManagerImpl::verify AccessToken failed");
    return false;
}
} // namespace EDM
} // namespace OHOS