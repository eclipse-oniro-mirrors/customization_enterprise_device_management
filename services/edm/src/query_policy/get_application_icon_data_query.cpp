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

#include "bundle_mgr_proxy.h"
#include "bundle_resource_proxy.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "edm_sys_manager.h"

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
    reply.WriteInt32(ERR_OK);
    reply.WriteString(iconData);
    return ERR_OK;
}

ErrCode GetApplicationIconDataQuery::GetApplicationIconFromBms(const std::string &bundleName,
    std::string &iconData, int32_t userId)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (!bundleMgrProxy) {
        EDMLOGE("GetApplicationIconDataQuery::GetApplicationIconFromBms get bundle manager failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    bool isInstalled = false;
    ErrCode checkResult = bundleMgrProxy->IsBundleInstalled(bundleName, userId, 0, isInstalled);
    if (FAILED(checkResult)) {
        EDMLOGE("GetApplicationIconDataQuery::GetApplicationIconFromBms check installed failed, bundleName:"
            "%{public}s, result:%{public}d", bundleName.c_str(), checkResult);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    if (!isInstalled) {
        EDMLOGE("GetApplicationIconDataQuery::GetApplicationIconFromBms application not installed, bundleName:"
            "%{public}s", bundleName.c_str());
        return EdmReturnErrCode::DOCK_APP_NOT_INSTALLED;
    }
    auto bundleResourceProxy = bundleMgrProxy->GetBundleResourceProxy();
    if (!bundleResourceProxy) {
        EDMLOGE("GetApplicationIconDataQuery::GetApplicationIconFromBms get bundle resource proxy failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    uint32_t flags = static_cast<uint32_t>(AppExecFwk::ResourceFlag::GET_RESOURCE_INFO_WITH_ICON);
    AppExecFwk::BundleResourceInfo bundleResourceInfo;
    ErrCode resourceResult = bundleResourceProxy->GetBundleResourceInfo(bundleName, flags, bundleResourceInfo);
    if (FAILED(resourceResult)) {
        EDMLOGW("GetApplicationIconDataQuery::GetApplicationIconFromBms get bundle resource failed, bundleName:"
            "%{public}s, result:%{public}d", bundleName.c_str(), resourceResult);
        iconData = "";
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    iconData = bundleResourceInfo.icon;
    EDMLOGI("GetApplicationIconDataQuery::GetApplicationIconFromBms get icon size:%{public}zu",
        iconData.size());
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
