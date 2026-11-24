/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "get_application_icon_data_query.h"

#include <string>

#include <system_ability_definition.h>

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "bundle_mgr_proxy.h"
#include "bundle_resource_proxy.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "ipc_skeleton.h"
#ifdef OS_ACCOUNT_EDM_ENABLE
#include "os_account_manager.h"
#endif

namespace OHOS {
namespace EDM {

std::string GetApplicationIconDataQuery::GetPolicyName()
{
    return PolicyName::POLICY_GET_APPLICATION_ICON_DATA;
}

std::string GetApplicationIconDataQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION;
}

ErrCode GetApplicationIconDataQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::string bundleName = data.ReadString();
    EDMLOGI("GetApplicationIconDataQuery::QueryPolicy bundleName:%{public}s", bundleName.c_str());
    std::string iconData;
    ErrCode result = GetApplicationIconFromBms(bundleName, iconData, userId);
    if (FAILED(result)) {
        return result;
    }
    if (iconData.size() > EdmConstants::MAX_IPC_RAWDATA_SIZE) {
        EDMLOGE("GetApplicationIconDataQuery::QueryPolicy icon data exceeds max ipc size, size:%{public}zu",
            iconData.size());
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    if (!reply.WriteInt32(ERR_OK) || !reply.WriteInt32(static_cast<int32_t>(iconData.size()))) {
        EDMLOGE("GetApplicationIconDataQuery::QueryPolicy write icon data size failed, size:%{public}zu",
            iconData.size());
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    // Raw data larger than MIN_RAWDATA_SIZE is transferred through ashmem automatically.
    if (!iconData.empty() && !reply.WriteRawData(iconData.data(), iconData.size())) {
        EDMLOGE("GetApplicationIconDataQuery::QueryPolicy write icon data failed, size:%{public}zu",
            iconData.size());
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}

ErrCode GetApplicationIconDataQuery::CheckBundleInstalledForUser(const sptr<AppExecFwk::IBundleMgr> &bundleMgrProxy,
    const std::string &bundleName, int32_t userId)
{
    AppExecFwk::BundleInfo bundleInfo;
    int32_t bundleInfoFlags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT);
    ErrCode checkRet = bundleMgrProxy->GetBundleInfoV9(bundleName, bundleInfoFlags, bundleInfo, userId);
    if (checkRet == ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST || checkRet == ERR_BUNDLE_MANAGER_INVALID_USER_ID) {
        EDMLOGW("GetApplicationIconDataQuery::CheckBundleInstalledForUser bundle not installed for user:"
            "%{public}d, bundleName:%{public}s", userId, bundleName.c_str());
        return EdmReturnErrCode::DOCK_APP_NOT_INSTALLED;
    }
    if (checkRet == ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED) {
        EDMLOGW("GetApplicationIconDataQuery::CheckBundleInstalledForUser extension unsupported,"
            " skip account check, bundleName:%{public}s", bundleName.c_str());
        return ERR_OK;
    }
    if (FAILED(checkRet)) {
        EDMLOGE("GetApplicationIconDataQuery::CheckBundleInstalledForUser get bundle info failed, ret:%{public}d",
            checkRet);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}

ErrCode GetApplicationIconDataQuery::GetApplicationIconFromBms(const std::string &bundleName,
    std::string &iconData, int32_t userId)
{
    // NOTE: Do NOT pre-check with IBundleMgr::IsBundleInstalled here.
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (!bundleMgrProxy) {
        EDMLOGE("GetApplicationIconDataQuery::GetApplicationIconFromBms get bundle manager failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    // GetBundleResourceInfo itself has no userId parameter, so verify the bundle is installed for the user.
    ErrCode ret = CheckBundleInstalledForUser(bundleMgrProxy, bundleName, userId);
    if (FAILED(ret)) {
        return ret;
    }
    auto bundleResourceProxy = bundleMgrProxy->GetBundleResourceProxy();
    if (!bundleResourceProxy) {
        EDMLOGE("GetApplicationIconDataQuery::GetApplicationIconFromBms get bundle resource proxy failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    uint32_t flags = static_cast<uint32_t>(AppExecFwk::ResourceFlag::GET_RESOURCE_INFO_WITH_ICON);
    AppExecFwk::BundleResourceInfo bundleResourceInfo;
    ErrCode resourceResult = bundleResourceProxy->GetBundleResourceInfo(bundleName, flags, bundleResourceInfo);
    if (resourceResult == ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST) {
        EDMLOGW("GetApplicationIconDataQuery::GetApplicationIconFromBms bundle not exist, bundleName:%{public}s",
            bundleName.c_str());
        return EdmReturnErrCode::DOCK_APP_NOT_INSTALLED;
    }
    if (FAILED(resourceResult)) {
        EDMLOGW("GetApplicationIconDataQuery::GetApplicationIconFromBms get bundle resource failed, bundleName:"
            "%{public}s, result:%{public}d", bundleName.c_str(), resourceResult);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    iconData = bundleResourceInfo.icon;
    EDMLOGI("GetApplicationIconDataQuery::GetApplicationIconFromBms get icon size:%{public}zu",
        iconData.size());
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
