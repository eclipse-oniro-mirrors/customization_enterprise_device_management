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
        return true;
    }
    EDMLOGE("EdmAccessTokenManagerImpl::not system app or native process");
    return false;
}

bool EdmAccessTokenManagerImpl::IsNativeCall()
{
    Security::AccessToken::ATokenTypeEnum tokenType =
        Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(IPCSkeleton::GetCallingTokenID());
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        return true;
    }
    EDMLOGI("EdmAccessTokenManagerImpl:: IsNativeCall not native process");
    return false;
}

bool EdmAccessTokenManagerImpl::IsSystemAppCall()
{
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(IPCSkeleton::GetCallingFullTokenID());
}

bool EdmAccessTokenManagerImpl::VerifyCallingPermission(Security::AccessToken::AccessTokenID tokenId,
    const std::string &permissionName)
{
    EDMLOGD("EdmAccessTokenManagerImpl::VerifyCallingPermission permission %{public}s", permissionName.c_str());
    int32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permissionName);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        EDMLOGI("EdmAccessTokenManagerImpl::permission %{public}s: PERMISSION_GRANTED", permissionName.c_str());
        return true;
    }
    EDMLOGW("EdmAccessTokenManagerImpl::verify AccessToken failed");
    return false;
}

bool EdmAccessTokenManagerImpl::GetAccessTokenId(int32_t userId, const std::string &appId, int32_t appIndex,
    Security::AccessToken::AccessTokenID &accessTokenId)
{
    std::string bundleName;
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        EDMLOGE("PermissionManagedStateQuery GetAccessTokenId: appControlProxy failed.");
        return false;
    }

    ErrCode res = proxy->GetBundleNameByAppId(appId, bundleName);
    if (res != ERR_OK) {
        EDMLOGE("PermissionManagedStateQuery GetAccessTokenId: GetBundleNameByAppId failed.");
        return false;
    }

    accessTokenId = Security::AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, appIndex);
    if (accessTokenId == Security::AccessToken::INVALID_TOKENID) {
        EDMLOGE("PermissionManagedStateQuery GetAccessTokenId: accessTokenId failed.");
        return false;
    }

    return true;
}

std::string EdmAccessTokenManagerImpl::GetHapTokenBundleName(Security::AccessToken::AccessTokenID tokenId)
{
    Security::AccessToken::HapTokenInfo hapTokenInfo;
    if (FAILED(Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo))) {
        EDMLOGE("EdmAccessTokenManagerImpl GetHapTokenInfo failed.");
        return "";
    }
    return hapTokenInfo.bundleName;
}
} // namespace EDM
} // namespace OHOS