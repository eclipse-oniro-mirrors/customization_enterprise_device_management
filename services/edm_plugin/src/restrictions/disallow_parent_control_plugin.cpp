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

#include "disallow_parent_control_plugin.h"

#include <algorithm>
#include <system_ability_definition.h>

#include "application_instance.h"
#include "bundle_mgr_interface.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "manage_apps_serializer.h"
#include "parameters.h"
#include "iext_info_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisallowParentControlPlugin>());

DisallowParentControlPlugin::DisallowParentControlPlugin()
{
    EDMLOGI("DisallowParentControlPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOW_PARENT_CONTROL;
    policyName_ = PolicyName::POLICY_DISALLOW_PARENT_CONTROL;
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    persistParam_ = "persist.edm.parent_control_disable";
}

ErrCode DisallowParentControlPlugin::CheckConflictPolicy(int32_t userId)
{
    ErrCode ret = CheckConflictWithNonStop(userId);
    if (FAILED(ret)) {
        EDMLOGE("DisallowParentControlPlugin CheckConflictPolicy CheckConflictWithNonStop faile or conflict");
        return ret;
    }
    return ERR_OK;
}

ErrCode DisallowParentControlPlugin::CheckConflictWithNonStop(int32_t userId)
{
    std::string policyData;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_MANAGE_USER_NON_STOP_APPS, policyData);
    std::vector<ApplicationInstance> apps;
    if (!ManageAppsSerializer::GetInstance()->Deserialize(policyData, apps)) {
        EDMLOGE("DisallowParentControlPlugin CheckConflictWithNonStop ManageAppsSerializer error");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (apps.empty()) {
        return ERR_OK;
    }
    if (std::find_if(apps.begin(), apps.end(), [&](const auto& item) {
        return item.accountId == userId && item.bundleName == IExtInfoManager::parentControlBundleName;
        }) != apps.end()) {
        EDMLOGE("DisallowParentControlPlugin CheckConflictWithNonStop CONFLICT WITH USER_NON_STOP");
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    return ERR_OK;
}

ErrCode DisallowParentControlPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisallowParentControlPlugin SetOtherModulePolicy data:%{public}d, userId: %{public}d", data, userId);
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    auto iBundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        EDMLOGE("DisallowParentControlPlugin can not get iBundleMgr");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    ErrCode ret = iBundleMgr->SetApplicationEnabled(IExtInfoManager::parentControlBundleName, !data, userId);
    if (FAILED(ret)) {
        EDMLOGE("DisallowParentControlPlugin SetApplicationEnabled failed:%{public}d", ret);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}

ErrCode DisallowParentControlPlugin::OnGetPolicy(std::string& policyData, MessageParcel& data,
    MessageParcel& reply, int32_t userId)
{
    EDMLOGI("DisallowParentControlPlugin OnGetPolicy ");
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(system::GetBoolParameter(persistParam_, false));
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS