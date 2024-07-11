/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "inactive_user_freeze_plugin.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(InactiveUserFreezePlugin::GetPlugin());
const std::string PERSIST_INACTIVE_USER_FREEZE_CONTROL = "persist.edm.inactive_user_freeze";

void InactiveUserFreezePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<InactiveUserFreezePlugin, bool>> ptr)
{
    EDMLOGI("InactiveUserFreezePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::INACTIVE_USER_FREEZE, "inactive_user_freeze",
        "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&InactiveUserFreezePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode InactiveUserFreezePlugin::OnSetPolicy(bool &data)
{
    EDMLOGI("InactiveUserFreezePlugin OnSetPolicy %{public}d", data);
    std::string value = data ? "true" : "false";
    if (!system::SetParameter(PERSIST_INACTIVE_USER_FREEZE_CONTROL, value)) {
        EDMLOGE("InactiveUserFreezePlugin::OnSetPolicy set sysparam failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode InactiveUserFreezePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    bool ret = system::GetBoolParameter(PERSIST_INACTIVE_USER_FREEZE_CONTROL, false);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(ret);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
