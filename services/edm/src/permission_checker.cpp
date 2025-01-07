/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "permission_checker.h"

#include "edm_log.h"
#include "access_token.h"
#include "ipc_skeleton.h"
#include "edm_constants.h"
#include "admin_manager.h"
#include "permission_manager.h"

namespace OHOS {
namespace EDM {

std::shared_ptr<PermissionChecker> PermissionChecker::instance_;
std::once_flag PermissionChecker::flag_;

std::shared_ptr<PermissionChecker> PermissionChecker::GetInstance()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_.reset(new (std::nothrow) PermissionChecker());
        }
    });
    return instance_;
}

std::shared_ptr<IExternalManagerFactory> PermissionChecker::GetExternalManagerFactory()
{
    return externalManagerFactory_;
}

ErrCode PermissionChecker::CheckCallerPermission(std::shared_ptr<Admin> admin, const std::string &permission,
    bool isNeedSuperAdmin)
{
    if (admin == nullptr) {
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (!GetExternalManagerFactory()->CreateAccessTokenManager()->VerifyCallingPermission(tokenId, permission)) {
        EDMLOGE("CheckCallerPermission verify calling permission failed.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    if (FAILED(CheckCallingUid(admin->adminInfo_.packageName_))) {
        EDMLOGE("CheckCallerPermission check calling uid failed.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    if (isNeedSuperAdmin && admin->GetAdminType() != AdminType::ENT) {
        EDMLOGE("CheckCallerPermission caller not a super admin.");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (!isNeedSuperAdmin && admin->GetAdminType() == AdminType::VIRTUAL_ADMIN) {
        EDMLOGE("CheckCallerPermission delegated admin does not have permission to handle.");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (!isNeedSuperAdmin && admin->GetAdminType() == AdminType::BYOD) {
        EDMLOGE("CheckCallerPermission byod admin does not have permission to handle.");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode PermissionChecker::CheckCallingUid(const std::string &bundleName)
{
    // super admin can be removed by itself
    int uid = IPCSkeleton::GetCallingUid();
    std::string callingBundleName;
    if (GetExternalManagerFactory()->CreateBundleManager()->GetNameForUid(uid, callingBundleName) != ERR_OK) {
        EDMLOGW("CheckCallingUid failed: get bundleName for uid %{public}d fail.", uid);
        return ERR_EDM_PERMISSION_ERROR;
    }
    if (bundleName == callingBundleName) {
        return ERR_OK;
    }
    EDMLOGW("CheckCallingUid failed: only the app %{public}s can remove itself.", callingBundleName.c_str());
    return ERR_EDM_PERMISSION_ERROR;
}


ErrCode PermissionChecker::CheckSystemCalling(IPlugin::ApiType apiType, const std::string &permissionTag)
{
    bool isCheckSystem = (apiType == IPlugin::ApiType::SYSTEM)
        || (permissionTag == EdmConstants::PERMISSION_TAG_SYSTEM_API);
    if (isCheckSystem && !CheckIsSystemAppOrNative()) {
        EDMLOGE("CheckSystemCalling: not system app or native process");
        return EdmReturnErrCode::SYSTEM_API_DENIED;
    }
    return ERR_OK;
}


ErrCode PermissionChecker::GetAllPermissionsByAdmin(const std::string &bundleInfoName, AdminType adminType,
    int32_t userId, std::vector<std::string> &permissionList)
{
    permissionList.clear();
    AppExecFwk::BundleInfo bundleInfo;
    EDMLOGD("GetAllPermissionsByAdmin GetBundleInfo: bundleInfoName %{public}s userid %{public}d",
        bundleInfoName.c_str(), userId);
    bool ret = GetExternalManagerFactory()->CreateBundleManager()->GetBundleInfo(bundleInfoName,
        AppExecFwk::BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION, bundleInfo, userId);
    if (!ret) {
        EDMLOGW("GetAllPermissionsByAdmin: GetBundleInfo failed %{public}d", ret);
        return ERR_EDM_PARAM_ERROR;
    }
    PermissionManager::GetInstance()->GetAdminGrantedPermission(bundleInfo.reqPermissions, adminType, permissionList);
    return ERR_OK;
}

ErrCode PermissionChecker::CheckHandlePolicyPermission(FuncOperateType operateType,
    const std::string &bundleName, const std::string &policyName, const std::string &permissionName, int32_t userId)
{
    if (operateType == FuncOperateType::SET && permissionName.empty()) {
        EDMLOGE("CheckHandlePolicyPermission failed, set policy need permission.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    if (permissionName == NONE_PERMISSION_MATCH) {
        EDMLOGE("CheckHandlePolicyPermission: GetPermission failed!");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::shared_ptr<Admin> deviceAdmin = AdminManager::GetInstance()->GetAdminByPkgName(bundleName, GetCurrentUserId());
    if (deviceAdmin == nullptr) {
        EDMLOGE("CheckHandlePolicyPermission: get admin failed");
        return EdmReturnErrCode::ADMIN_INACTIVE;
    }
    if (FAILED(CheckCallingUid(deviceAdmin->adminInfo_.packageName_))) {
        EDMLOGE("CheckHandlePolicyPermission: CheckCallingUid failed.");
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    if (operateType == FuncOperateType::SET && deviceAdmin->GetAdminType() != AdminType::ENT &&
        deviceAdmin->GetAdminType() != AdminType::SUB_SUPER_ADMIN &&
        deviceAdmin->GetAdminType() != AdminType::VIRTUAL_ADMIN && userId != GetCurrentUserId()) {
        EDMLOGE("CheckHandlePolicyPermission: this admin does not have permission to handle policy of other account.");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (!permissionName.empty()) {
        auto ret = CheckAndUpdatePermission(deviceAdmin, IPCSkeleton::GetCallingTokenID(), permissionName, userId);
        if (FAILED(ret)) {
            return ret;
        }
    }
    if (!AdminManager::GetInstance()->HasPermissionToHandlePolicy(deviceAdmin, policyName)) {
        EDMLOGE("CheckHandlePolicyPermission: this admin does not have permission to handle the policy.");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode PermissionChecker::CheckAndUpdatePermission(std::shared_ptr<Admin> admin,
    Security::AccessToken::AccessTokenID tokenId, const std::string &permission, int32_t userId)
{
    if (admin == nullptr) {
        EDMLOGE("CheckHandlePolicyPermission: this admin does not have permission to handle the policy.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool callingPermission = VerifyCallingPermission(tokenId, permission);
    bool adminPermission = admin->CheckPermission(permission);
    if (callingPermission != adminPermission) {
        std::vector<std::string> permissionList;
        if (FAILED(GetAllPermissionsByAdmin(admin->adminInfo_.packageName_,
            admin->GetAdminType(), userId, permissionList))) {
            EDMLOGE("CheckAndUpdatePermission get all permission that admin request failed.");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        auto hasPermission = std::find(permissionList.begin(), permissionList.end(), permission);
        if (!callingPermission && hasPermission != permissionList.end()) {
            EDMLOGE("CheckAndUpdatePermission access token check abnormally.");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        if (!adminPermission && hasPermission == permissionList.end()) {
            EDMLOGE("CheckAndUpdatePermission this admin does not have the permission.");
            return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
        }
        Admin updateAdmin(admin->adminInfo_.packageName_, admin->GetAdminType(), permissionList);
        updateAdmin.SetAccessiblePolicies(admin->adminInfo_.accessiblePolicies_);
        if (FAILED(AdminManager::GetInstance()->UpdateAdmin(admin, userId, updateAdmin))) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    if (!callingPermission) {
        return EdmReturnErrCode::PERMISSION_DENIED;
    }
    return ERR_OK;
}

int32_t PermissionChecker::GetCurrentUserId()
{
    std::vector<int32_t> ids;
    auto fac = GetExternalManagerFactory();
    ErrCode ret = fac->CreateOsAccountManager()->QueryActiveOsAccountIds(ids);
    if (FAILED(ret) || ids.empty()) {
        EDMLOGE("PermissionChecker GetCurrentUserId failed");
        return -1;
    }
    EDMLOGD("PermissionChecker GetCurrentUserId user id = %{public}d", ids.at(0));
    return (ids.at(0));
}

IPlugin::PermissionType PermissionChecker::AdminTypeToPermissionType(AdminType adminType)
{
    if (adminType == AdminType::BYOD) {
        return IPlugin::PermissionType::BYOD_DEVICE_ADMIN;
    }
    return IPlugin::PermissionType::SUPER_DEVICE_ADMIN;
}

bool PermissionChecker::CheckIsDebug()
{
    return GetExternalManagerFactory()->CreateAccessTokenManager()->IsDebug();
}

bool PermissionChecker::CheckIsSystemAppOrNative()
{
    return GetExternalManagerFactory()->CreateAccessTokenManager()->IsSystemAppOrNative();
}

bool PermissionChecker::VerifyCallingPermission(Security::AccessToken::AccessTokenID tokenId,
    const std::string &permissionName)
{
    return GetExternalManagerFactory()->CreateAccessTokenManager()->VerifyCallingPermission(tokenId, permissionName);
}
} // namespace EDM
} // namespace OHOS
