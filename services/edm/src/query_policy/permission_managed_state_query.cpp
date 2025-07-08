/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#include "permission_managed_state_info.h"

#include "edm_bundle_manager_impl.h"
#include "edm_log.h"

#include "app_control/app_control_proxy.h"
#include <system_ability_definition.h>
#include "edm_sys_manager.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_interface.h"
#include "accesstoken_kit.h"

namespace OHOS {
namespace EDM {
ErrCode GetAccessTokenId(int32_t userId, const std::string &appId, int32_t appIndex,
    Security::AccessToken::AccessTokenID &accessTokenId)
{
    std::string bundleName;
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        EDMLOGE("PermissionManagedStateQuery GetAccessTokenId: appControlProxy failed.");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    ErrCode res = proxy->GetBundleNameByAppId(appId, bundleName);
    if (res != ERR_OK) {
        EDMLOGE("PermissionManagedStateQuery GetAccessTokenId: GetBundleNameByAppId failed.");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    accessTokenId = Security::AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, appIndex);
    if (accessTokenId == Security::AccessToken::INVALID_TOKENID) {
        EDMLOGE("PermissionManagedStateQuery GetAccessTokenId: accessTokenId failed.");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    return ERR_OK;
}

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
    ErrCode res = GetAccessTokenId(info.accountId, info.appId, info.appIndex, accessTokenId);
    if (res != ERR_OK) {
        EDMLOGE("PermissionManagedStateQuery QueryPolicy GetAccessTokenId failed.");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    uint32_t permissionFlag;
    int32_t ret = Security::AccessToken::AccessTokenKit::GetPermissionFlag(
        accessTokenId,
        info.permissionName,
        permissionFlag);
    if (ret != Security::AccessToken::RET_SUCCESS) {
        EDMLOGE("PermissionManagedStateQuery QueryPolicy GetPermissionFlag failed.");
        return EdmReturnErrCode::PARAM_ERROR;
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
    return EdmReturnErrCode::PARAM_ERROR;
}
} // namespace EDM
} // namespace OHOS