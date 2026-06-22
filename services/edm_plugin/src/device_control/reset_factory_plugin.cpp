/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "reset_factory_plugin.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "update_service_kits.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<ResetFactoryPlugin>());
const std::string DISALLOWED_RESET_FACTORY_PARAM = "persist.edm.reset_factory_disallowed";

ResetFactoryPlugin::ResetFactoryPlugin()
{
    policyCode_ = EdmInterfaceCode::RESET_FACTORY;
    policyName_ = PolicyName::POLICY_RESET_FACTORY;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_RESET_DEVICE,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode ResetFactoryPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    std::string isDisabled = OHOS::system::GetParameter(DISALLOWED_RESET_FACTORY_PARAM, EdmConstants::CONST_FALSE);
    if (isDisabled == EdmConstants::CONST_TRUE) {
        EDMLOGE("ResetFactoryPlugin:OnHandlePolicy factory reset is disabled by restriction");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    UpdateService::BusinessError businessError;
    int32_t ret = UpdateService::UpdateServiceKits::GetInstance().ForceFactoryReset(businessError);
    if (FAILED(ret)) {
        EDMLOGE("ResetFactoryPlugin:OnHandlePolicy send request fail. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
