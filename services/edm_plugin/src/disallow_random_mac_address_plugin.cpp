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

#include "disallow_random_mac_address_plugin.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "StaService.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    DisallowRandomMacAddressPlugin::GetPlugin());

void DisallowRandomMacAddressPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowRandomMacAddressPlugin, bool>> ptr)
{
    EDMLOGI("DisallowRandomMacAddressPlugin InitPlugin...");
    ptr->InitAttribute(
        EdmInterfaceCode::DISALLOWED_RANDOM_MAC_ADDRESS,
        PolicyName::POLICY_DISALLOWED_RANDOM_MAC_ADDRESS,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowRandomMacAddressPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowRandomMacAddressPlugin::OnAdminRemove);
    persistParam_ = "persist.edm.random_mac_address_disable";
}

ErrCode DisallowRandomMacAddressPlugin::OnSetPolicy(bool &data, bool &currentData, bool &mergePolicy, int32_t userId)
{
    EDMLOGI("DisallowRandomMacAddressPlugin OnSetPolicy");
    if (mergePolicy) {
        currentData = data;
        return ERR_OK;
    }
    if (!system::SetParameter(persistParam_, data ? "true" : "false")) {
        EDMLOGE("DisallowRandomMacAddressPlugin set param failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (data) {
        ErrCode Ret = SetOtherModulePolicy(data, userId);
        if (FAILED(Ret)) {
            return Ret;
        }
    }
    currentData = data;
    mergePolicy = data;
    return ERR_OK;
}

ErrCode DisallowRandomMacAddressPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisallowRandomMacAddressPlugin SetOtherModulePolicy");
    if (data) {
        ErrCode Ret = OHOS::wifi::StaService::GetInstance.SetRandomMacDisable(data);
        if (Ret != ERR_OK) {
            EDMLOGI("DisallowRandomMacAddressPlugin: unmount storage device failed ret: %{public}d", Ret);
            return Ret;
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS