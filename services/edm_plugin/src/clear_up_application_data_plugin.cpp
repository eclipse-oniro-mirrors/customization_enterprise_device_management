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

#include "clear_up_application_data_plugin.h"

#include "app_mgr_proxy.h"
#include "clear_up_application_data_param_serializer.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(ClearUpApplicationDataPlugin::GetPlugin());

void ClearUpApplicationDataPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<ClearUpApplicationDataPlugin, ClearUpApplicationDataParam>> ptr)
{
    EDMLOGI("ClearUpApplicationDataPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::CLEAR_UP_APPLICATION_DATA, PolicyName::POLICY_CLEAR_UP_APPLICATION_DATA,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(ClearUpApplicationDataParamSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&ClearUpApplicationDataPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode ClearUpApplicationDataPlugin::OnSetPolicy(ClearUpApplicationDataParam &param)
{
    EDMLOGD("ClearUpApplicationDataPlugin::OnSetPolicy, bundleName = %{public}s", param.bundleName.c_str());
    sptr<ISystemAbilityManager> abilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (abilityMgr == nullptr) {
        EDMLOGE("Failed to get ISystemAbilityManager");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<IRemoteObject> remoteObject = abilityMgr->CheckSystemAbility(APP_MGR_SERVICE_ID);
    if (remoteObject == nullptr) {
        EDMLOGE("Failed to get app manager service");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<AppExecFwk::IAppMgr> appMgrProxy = iface_cast<AppExecFwk::IAppMgr>(remoteObject);
    if (appMgrProxy == nullptr || !appMgrProxy->AsObject()) {
        EDMLOGE("Failed to get app mgr proxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int ret = appMgrProxy->ClearUpApplicationData(param.bundleName, param.appIndex, param.userId);
    EDMLOGI("ClearUpApplicationData ret: %{public}d", ret);
    if (ret != 0) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
