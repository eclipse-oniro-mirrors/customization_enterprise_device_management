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

#include "disallowed_traffic_redirection_plugin.h"

#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "netfirewall_client.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
// LCOV_EXCL_START
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowedTrafficRedirectionPlugin::GetPlugin());

void DisallowedTrafficRedirectionPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowedTrafficRedirectionPlugin, bool>> ptr)
{
    EDMLOGI("DisallowedTrafficRedirectionPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_TRAFFIC_REDIRECTION,
        PolicyName::POLICY_DISALLOWED_TRAFFIC_REDIRECTION,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedTrafficRedirectionPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowedTrafficRedirectionPlugin::OnAdminRemove);
}

ErrCode DisallowedTrafficRedirectionPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisallowedTrafficRedirectionPlugin SetOtherModulePolicy");
    int32_t ret = ERR_OK;
    if (data) {
        ret = OHOS::NetManagerStandard::NetFirewallClient::GetInstance().GlobalDisableTrafficFilter();
    } else {
        ret = OHOS::NetManagerStandard::NetFirewallClient::GetInstance().GlobalEnableTrafficFilter();
    }
    if (ret != ERR_OK) {
        EDMLOGE("DisallowedTrafficRedirectionPlugin SetOtherModulePolicy traffic filter error.%{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode DisallowedTrafficRedirectionPlugin::RemoveOtherModulePolicy(int32_t userId)
{
    EDMLOGI("DisallowedTrafficRedirectionPlugin RemoveOtherModulePolicy");
    int32_t ret = OHOS::NetManagerStandard::NetFirewallClient::GetInstance().GlobalEnableTrafficFilter();
    if (ret != ERR_OK) {
        EDMLOGE("DisallowedTrafficRedirectionPlugin RemoveOtherModulePolicy traffic filter error.%{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
// LCOV_EXCL_STOP
} // namespace EDM
} // namespace OHOS