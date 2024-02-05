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

#include "disallow_modify_datetime_plugin.h"

#include "edm_ipc_interface_code.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(DisallModifyDateTimePlugin::GetPlugin());

void DisallModifyDateTimePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisallModifyDateTimePlugin, bool>> ptr)
{
    EDMLOGI("DisallModifyDateTimePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOW_MODIFY_DATETIME, "disallow_modify_datetime",
        "ohos.permission.ENTERPRISE_SET_DATETIME", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallModifyDateTimePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode DisallModifyDateTimePlugin::OnSetPolicy(bool &data)
{
    return ERR_OK;
}

ErrCode DisallModifyDateTimePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    bool disallow = false;
    pluginInstance_->serializer_->Deserialize(policyData, disallow);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(disallow);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
