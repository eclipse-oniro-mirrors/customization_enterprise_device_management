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

#include "disallowed_tethering_plugin.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(DisallowedTetheringPlugin::GetPlugin());
const std::string PERSIST_TETHERING_CONTROL = "persist.edm.tethering_disallowed";

void DisallowedTetheringPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisallowedTetheringPlugin, bool>> ptr)
{
    EDMLOGI("DisallowedTetheringPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_TETHERING, "disallowed_tethering",
        "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedTetheringPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode DisallowedTetheringPlugin::OnSetPolicy(bool &data)
{
    EDMLOGI("DisallowedTetheringPlugin OnSetPolicy %{public}d", data);
    std::string value = data ? "true" : "false";
    return system::SetParameter(PERSIST_TETHERING_CONTROL, value) ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode DisallowedTetheringPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    bool ret = system::GetBoolParameter(PERSIST_TETHERING_CONTROL, true);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(ret);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
