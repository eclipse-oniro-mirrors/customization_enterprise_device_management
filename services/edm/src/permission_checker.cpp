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

#include "access_token.h"
#include "admin_manager.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "ipc_skeleton.h"
#include "permission_manager.h"

namespace OHOS {
namespace EDM {

std::shared_ptr<PermissionChecker> PermissionChecker::instance_;
std::once_flag PermissionChecker::flag_;

std::vector<uint32_t> PermissionChecker::supportAdminNullPolicyCode_ = {
    EdmInterfaceCode::DISALLOW_ADD_OS_ACCOUNT_BY_USER,
    EdmInterfaceCode::DISALLOW_ADD_LOCAL_ACCOUNT,
    EdmInterfaceCode::DISABLE_BLUETOOTH,
    EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES,
    EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES,
    EdmInterfaceCode::SET_BROWSER_POLICIES,
    EdmInterfaceCode::MANAGED_BROWSER_POLICY,
    EdmInterfaceCode::DISALLOW_MODIFY_DATETIME,
    EdmInterfaceCode::LOCATION_POLICY,
    EdmInterfaceCode::FINGERPRINT_AUTH,
    EdmInterfaceCode::DISABLE_MICROPHONE,
    EdmInterfaceCode::DISABLED_PRINTER,
    EdmInterfaceCode::DISABLED_HDC,
    EdmInterfaceCode::DISABLE_USB,
    EdmInterfaceCode::DISALLOWED_USB_DEVICES,
    EdmInterfaceCode::USB_READ_ONLY,
    EdmInterfaceCode::ALLOWED_USB_DEVICES,
    EdmInterfaceCode::DISABLE_WIFI,
    EdmInterfaceCode::DISABLE_MTP_CLIENT,
    EdmInterfaceCode::DISABLE_MTP_SERVER,
    EdmInterfaceCode::DISABLE_SAMBA_CLIENT,
    EdmInterfaceCode::DISABLE_SAMBA_SERVER,
    EdmInterfaceCode::DISALLOWED_TETHERING,
    EdmInterfaceCode::INACTIVE_USER_FREEZE,
    EdmInterfaceCode::DISABLE_CAMERA,
    EdmInterfaceCode::PASSWORD_POLICY,
    EdmInterfaceCode::DISABLE_REMOTE_DESK,
    EdmInterfaceCode::DISABLE_REMOTE_DIAGNOSIS,
    EdmInterfaceCode::DISABLE_SET_BIOMETRICS_AND_SCREENLOCK,
    EdmInterfaceCode::DISABLE_SET_DEVICE_NAME,
    EdmInterfaceCode::DISABLE_MAINTENANCE_MODE,
    EdmInterfaceCode::DISALLOWED_SMS,
    EdmInterfaceCode::DISALLOWED_MMS,
    EdmInterfaceCode::DISABLE_BACKUP_AND_RESTORE,
    EdmInterfaceCode::IS_APP_KIOSK_ALLOWED,
    EdmInterfaceCode::DISALLOWED_MOBILE_DATA,
    EdmInterfaceCode::DISALLOWED_AIRPLANE_MODE,
    EdmInterfaceCode::DISALLOW_MODIFY_ETHERNET_IP,
    EdmInterfaceCode::DISALLOWED_SUDO,
    EdmInterfaceCode::DISABLE_PRIVATE_SPACE,
    EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISALLOW_SCREEN_SHOT,
    EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISALLOW_SCREEN_RECORD,
    EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISABLE_DISK_RECOVERY_KEY,
    EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISALLOW_NEAR_LINK,
    EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISABLE_DEVELOPER_MODE,
    EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISABLE_RESET_FACTORY,
    EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISALLOWED_NFC,
    EdmInterfaceCode::DISALLOW_VPN,
    EdmInterfaceCode::DISALLOWED_NOTIFICATION,
    EdmInterfaceCode::DISALLOWED_TELEPHONY_CALL,
    EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISABLE_OTA,
};

std::unordered_set<std::string> PermissionChecker::allowDelegatedPolicies_ = {
    PolicyName::POLICY_DISALLOW_ADD_LOCAL_ACCOUNT, PolicyName::POLICY_DISALLOW_ADD_OS_ACCOUNT_BY_USER,
    PolicyName::POLICY_DISALLOW_RUNNING_BUNDLES, PolicyName::POLICY_MANAGE_AUTO_START_APPS,
    PolicyName::POLICY_ALLOWED_BLUETOOTH_DEVICES, PolicyName::POLICY_SET_BROWSER_POLICIES,
    PolicyName::POLICY_ALLOWED_INSTALL_BUNDLES, PolicyName::POLICY_DISALLOWED_INSTALL_BUNDLES,
    PolicyName::POLICY_DISALLOWED_UNINSTALL_BUNDLES, PolicyName::POLICY_SNAPSHOT_SKIP,
    PolicyName::POLICY_LOCATION_POLICY, PolicyName::POLICY_DISABLED_NETWORK_INTERFACE,
    PolicyName::POLICY_GLOBAL_PROXY, PolicyName::POLICY_DISABLED_BLUETOOTH,
    PolicyName::POLICY_DISALLOW_MODIFY_DATETIME, PolicyName::POLICY_DISABLED_PRINTER,
    PolicyName::POLICY_POLICY_SCREEN_SHOT, PolicyName::POLICY_DISABLED_HDC,
    PolicyName::POLICY_DISABLE_MICROPHONE, PolicyName::POLICY_FINGERPRINT_AUTH,
    PolicyName::POLICY_DISABLE_USB, PolicyName::POLICY_DISABLE_WIFI,
    PolicyName::POLICY_DISALLOWED_TETHERING, PolicyName::POLICY_INACTIVE_USER_FREEZE,
    PolicyName::POLICY_PASSWORD_POLICY, PolicyName::POLICY_CLIPBOARD_POLICY,
    PolicyName::POLICY_NTP_SERVER, PolicyName::POLICY_SET_UPDATE_POLICY,
    PolicyName::POLICY_NOTIFY_UPGRADE_PACKAGES, PolicyName::POLICY_ALLOWED_USB_DEVICES,
    PolicyName::POLICY_USB_READ_ONLY, PolicyName::POLICY_DISALLOWED_USB_DEVICES,
    PolicyName::POLICY_GET_DEVICE_INFO, PolicyName::POLICY_WATERMARK_IMAGE_POLICY,
    PolicyName::POLICY_POLICY_SCREEN_RECORD, PolicyName::POLICY_INSTALLED_BUNDLE_INFO_LIST,
    PolicyName::POLICY_ALLOW_ALL,
};

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

bool PermissionChecker::IsAllowDelegatedPolicy(const std::string &policy)
{
    return allowDelegatedPolicies_.find(policy) != allowDelegatedPolicies_.end();
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
    if (operateType == FuncOperateType::SET && deviceAdmin->GetAdminType() == AdminType::NORMAL &&
        userId != GetCurrentUserId()) {
        EDMLOGE("CheckHandlePolicyPermission: this admin does not have permission to handle policy of other account.");
        return EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED;
    }
    if (!permissionName.empty()) {
        EDMLOGI("CheckHandlePolicyPermission: permissionName:%{public}s", permissionName.c_str());
        auto ret = CheckAndUpdatePermission(deviceAdmin, IPCSkeleton::GetCallingTokenID(), permissionName, userId);
        if (FAILED(ret)) {
            return ret;
        }
    }
    if (permissionName.empty() && deviceAdmin->GetAdminType() == AdminType::BYOD) {
        return EdmReturnErrCode::PERMISSION_DENIED;
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
    EDMLOGI("CheckAndUpdatePermission::callingPermission: %{public}d.adminPermission:%{public}d", callingPermission,
        adminPermission);
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

bool PermissionChecker::CheckElementNullPermission(uint32_t funcCode, const std::string &permissionName)
{
    std::uint32_t code = FuncCodeUtils::GetPolicyCode(funcCode);
    auto item = std::find(supportAdminNullPolicyCode_.begin(), supportAdminNullPolicyCode_.end(), code);
    if (item == supportAdminNullPolicyCode_.end()) {
        EDMLOGE("PermissionChecker not support element null query code is %{public}d", code);
        return false;
    }
    if (permissionName.empty()) {
        return true;
    }
    if (CheckSpecialPolicyCallQuery(code)) {
        return true;
    }
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    if (!VerifyCallingPermission(tokenId, permissionName)) {
        EDMLOGE("PermissionChecker element null query no permission code is %{public}d", code);
        return false;
    }
    return true;
}

bool PermissionChecker::CheckSpecialPolicyCallQuery(uint32_t code)
{
    bool isSystemAppCall = GetExternalManagerFactory()->CreateAccessTokenManager()->IsSystemAppCall();
    if (isSystemAppCall) {
        return true;
    }
    bool isNativeCall = GetExternalManagerFactory()->CreateAccessTokenManager()->IsNativeCall();
    if (isNativeCall) {
        int uid = IPCSkeleton::GetCallingUid();
        if (code == EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES ||
            code == EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES) {
            return uid == EdmConstants::BLUETOOTH_SERVICE_UID;
        } else if (code == EdmInterfaceCode::PASSWORD_POLICY) {
            return uid == EdmConstants::USERIAM_SERVICE_UID;
        } else if (code == EdmInterfaceCode::DISABLE_USB) {
            return uid == EdmConstants::USB_SERVICE_UID;
        }
    }
    return false;
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
