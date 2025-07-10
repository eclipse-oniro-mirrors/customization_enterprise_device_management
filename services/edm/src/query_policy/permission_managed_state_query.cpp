/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "permission_managed_state_query.h"

#include "accesstoken_kit.h"

#include "edm_access_token_manager_impl.h"
#include "permission_managed_state_info.h"

namespace OHOS {
namespace EDM {
std::string PermissionManagedStateQuery::GetPolicyName()
{
    return PolicyName::POLICY_PERMISSION_MANAGED_STATE_POLICY;
}

std::string PermissionManagedStateQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USER_GRANT_PERMISSION;
}

ErrCode PermissionManagedStateQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("PermissionManagedStateQuery OnQueryPolicy");
    PermissionManagedStateInfo info;
    info.appId = data.ReadString();
    info.accountId = data.ReadInt32();
    info.appIndex = data.ReadInt32();
    info.permissionName = data.ReadString();

    Security::AccessToken::AccessTokenID accessTokenId;
    EdmAccessTokenManagerImpl edmAccessTokenManagerImpl;
    if (!edmAccessTokenManagerImpl.GetAccessTokenId(info.accountId, info.appId, info.appIndex, accessTokenId)) {
        EDMLOGE("PermissionManagedStateQuery QueryPolicy GetAccessTokenId failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    uint32_t permissionFlag;
    int32_t ret = Security::AccessToken::AccessTokenKit::GetPermissionFlag(
        accessTokenId,
        info.permissionName,
        permissionFlag);
    if (ret != Security::AccessToken::RET_SUCCESS) {
        EDMLOGE("PermissionManagedStateQuery QueryPolicy GetPermissionFlag failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (permissionFlag == Security::AccessToken::TypePermissionFlag::PERMISSION_ADMIN_POLICIES_CANCEL ||
        permissionFlag == Security::AccessToken::TypePermissionFlag::PERMISSION_DEFAULT_FLAG) {
        reply.WriteInt32(ERR_OK);
        reply.WriteInt32(static_cast<int32_t>(ManagedState::DEFAULT));
    } else {
        int32_t permissionState = Security::AccessToken::AccessTokenKit::VerifyAccessToken(accessTokenId,
            info.permissionName);
        if (permissionState == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
            reply.WriteInt32(ERR_OK);
            reply.WriteInt32(static_cast<int32_t>(ManagedState::GRANTED));
            return ERR_OK;
        } else if (permissionState == Security::AccessToken::PermissionState::PERMISSION_DENIED) {
            reply.WriteInt32(ERR_OK);
            reply.WriteInt32(static_cast<int32_t>(ManagedState::DENIED));
            return ERR_OK;
        }
    }
    return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
}
} // namespace EDM
} // namespace OHOS