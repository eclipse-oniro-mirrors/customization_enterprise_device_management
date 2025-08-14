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
#include "disallowed_sim_plugin.h"

#include "core_service_client.h"
#include "parameters.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
 
namespace OHOS {
namespace EDM {
 
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowedSimPlugin::GetPlugin());
const std::string PARAM_DISABLE_SLOT0 = "persist.edm.disable_slot_0";
const std::string PARAM_DISABLE_SLOT1 = "persist.edm.disable_slot_1";

constexpr uint32_t SOLT0_ID = 0;
constexpr uint32_t SOLT1_ID = 1;
#define SOLT0_BIT (1 << 0)
#define SOLT1_BIT (1 << 1)


void DisallowedSimPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisallowedSimPlugin, uint32_t>> ptr)
{
    EDMLOGI("DisallowedSimPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_SIM, "disallowed_sim",
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BitSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedSimPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&DisallowedSimPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&DisallowedSimPlugin::OnAdminRemove);
}
 
ErrCode DisallowedSimPlugin::OnSetPolicy(uint32_t &data, uint32_t &currentData, uint32_t &mergeData, int32_t userId)
{
    EDMLOGI("DisallowedSimPlugin OnSetPolicy slotId %{public}d", data);
    bool ret = false;
    if (data == SOLT0_ID) {
        currentData |= SOLT0_BIT;
        ret = system::SetParameter(PARAM_DISABLE_SLOT0, "true");
    } else if (data == SOLT1_ID) {
        currentData |= SOLT1_BIT;
        ret = system::SetParameter(PARAM_DISABLE_SLOT1, "true");
    } else {
        EDMLOGE("DisallowedSimPlugin:OnSetPolicy Parameter err, slotId %{public}d", data);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (!ret) {
        EDMLOGE("DisallowedSimPlugin:OnSetPolicy SetParameter fail, slotId %{public}d", data);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t simId = Telephony::CoreServiceClient::GetInstance().GetSimId(data);
    if (simId > 0) {
        Telephony::CoreServiceClient::GetInstance().SetActiveSim(data, 0);
    }
    mergeData |= currentData;

    return ERR_OK;
}

ErrCode DisallowedSimPlugin::OnRemovePolicy(uint32_t &data, uint32_t &currentData, uint32_t &mergeData, int32_t userId)
{
    EDMLOGI("DisallowedSimPlugin OnRemovePolicy slotId %{public}d", data);
    bool ret = false;
    if (data == SOLT0_ID) {
        currentData = currentData & ~SOLT0_BIT;
        if ((mergeData & SOLT0_BIT) == 0) {
            ret = system::SetParameter(PARAM_DISABLE_SLOT0, "false");
        }
    } else if (data == SOLT1_ID) {
        currentData = currentData & ~SOLT1_BIT;
        if ((mergeData & SOLT1_BIT) == 0) {
            ret = system::SetParameter(PARAM_DISABLE_SLOT1, "false");
        }
    } else {
        EDMLOGE("DisallowedSimPlugin:OnRemovePolicy Parameter err, slotId %{public}d", data);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (!ret) {
        EDMLOGE("DisallowedSimPlugin:OnRemovePolicy SetParameter fail, slotId %{public}d", data);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    mergeData |= currentData;
    
    return ERR_OK;
}

ErrCode DisallowedSimPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGD("DisallowedSimPlugin OnGetPolicy.");
    int32_t slotId = data.ReadInt32();
    
    bool isDisable = false;
    if (slotId == SOLT0_ID) {
        isDisable = system::GetBoolParameter(PARAM_DISABLE_SLOT0, false);
    } else if (slotId == SOLT1_ID) {
        isDisable = system::GetBoolParameter(PARAM_DISABLE_SLOT1, false);
    } else {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isDisable);

    return ERR_OK;
}

ErrCode DisallowedSimPlugin::OnAdminRemove(const std::string &adminName, uint32_t &data,
    uint32_t &mergeData, int32_t userId)
{
    EDMLOGI("DisallowedSimPlugin OnAdminRemove adminName : %{public}s, data : %{public}d",
            adminName.c_str(), data);
    if ((mergeData & SOLT0_BIT) == 0) {
        if (!system::SetParameter(PARAM_DISABLE_SLOT0, "false")) {
            EDMLOGE("DisallowedSimPlugin:OnAdminRemove slot0 SetParameter fail");
        }
    }
    if ((mergeData & SOLT1_BIT) == 0) {
        if (!system::SetParameter(PARAM_DISABLE_SLOT1, "false")) {
            EDMLOGE("DisallowedSimPlugin:OnAdminRemove slot1 SetParameter fail");
        }
    }
    
    return ERR_OK;
}

} // namespace EDM
} // namespace OHOS