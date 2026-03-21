/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "disallowed_notification_plugin.h"

#include "allowed_notification_bundles_serializer.h"
#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowedNotificationPlugin::GetPlugin());

void DisallowedNotificationPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisallowedNotificationPlugin, bool>> ptr)
{
    EDMLOGI("DisallowedNotificationPlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(typePermissions,
        IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_NOTIFICATION, PolicyName::POLICY_DISALLOWED_NOTIFICATION,
        config, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedNotificationPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowedNotificationPlugin::OnAdminRemove);
    persistParam_ = "persist.edm.notification_disable";
}

ErrCode DisallowedNotificationPlugin::CheckConflictPolicy()
{
    std::string policyData;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_ALLOWED_NOTIFICATION_BUNDLES,
        policyData, EdmConstants::DEFAULT_USER_ID);
    std::vector<AllowedNotificationBundlesType> data;
    if (!AllowedNotificationBundlesSerializer::GetInstance()->Deserialize(policyData, data)) {
        EDMLOGE("DisallowedNotificationPlugin::SetOtherModulePolicy Deserialize error");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (data.size() > 0) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
