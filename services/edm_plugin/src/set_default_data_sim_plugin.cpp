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

#include "set_default_data_sim_plugin.h"

#include "edm_constants.h"
#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"
#include "core_service_client.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {
const std::string PARAM_DISABLE_SLOT0 = "persist.edm.disable_slot_0";
const std::string PARAM_DISABLE_SLOT1 = "persist.edm.disable_slot_1";
constexpr uint32_t SOLT0_ID = 0;
constexpr uint32_t SOLT1_ID = 1;
const std::string AIRPLANE_MODE = "settings.telephony.airplanemode";
const std::string ACTIVE_AIRPLANE_MODE = "1";

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetDefaultDataSimPlugin::GetPlugin());

void SetDefaultDataSimPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetDefaultDataSimPlugin, int32_t>> ptr)
{
    EDMLOGI("SetDefaultDataSimPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::SET_DEFAULT_DATA_SIM, PolicyName::POLICY_SET_DEFAULT_DATA_SIM,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(IntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetDefaultDataSimPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode SetDefaultDataSimPlugin::OnSetPolicy(int32_t &slotId)
{
    EDMLOGI("SetDefaultDataSimPlugin OnSetPolicy slotId: %{public}d", slotId);
    
    int32_t maxSlotId = Telephony::CoreServiceClient::GetInstance().GetMaxSimCount();
    if (slotId < 0 || slotId >= maxSlotId) {
        EDMLOGE("SetDefaultDataSimPlugin::OnSetPolicy slotId is invalid: %{public}d", slotId);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    std::string value = "";
    ErrCode res = EdmDataAbilityUtils::GetStringFromSettingsDataShare(AIRPLANE_MODE, value);
    if (res != ERR_OK) {
        EDMLOGE("ManageSim get settings airplane mode failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (value == ACTIVE_AIRPLANE_MODE) {
        EDMLOGE("ManageSim current has active airplane mode");
        return EdmReturnErrCode::SET_DEFAULT_DATA_SIM_FAILED;
    }
    bool isDisable = false;
    if (slotId == SOLT0_ID) {
        isDisable = system::GetBoolParameter(PARAM_DISABLE_SLOT0, false);
    } else if (slotId == SOLT1_ID) {
        isDisable = system::GetBoolParameter(PARAM_DISABLE_SLOT1, false);
    } else {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (isDisable) {
        EDMLOGE("ManageSim current slotId : %{public}d has disabled", slotId);
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }
    
    int32_t ret = Telephony::CoreServiceClient::GetInstance().SetPrimarySlotId(slotId);
    if (ret != 0) {
        EDMLOGE("SetDefaultDataSimPlugin::OnSetPolicy SetPrimarySlotId failed, errCode is %{public}d.", ret);
        return EdmReturnErrCode::SET_DEFAULT_DATA_SIM_FAILED;
    }
    
    return ERR_OK;
}

ErrCode SetDefaultDataSimPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("SetDefaultDataSimPlugin OnGetPolicy.");
    int32_t slotId = -1;
    ErrCode ret = Telephony::CoreServiceClient::GetInstance().GetPrimarySlotId(slotId);
    if (ret != ERR_OK) {
        EDMLOGE("SetDefaultDataSimPlugin OnGetPolicy failed, error code : %{public}d.", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(slotId);
    EDMLOGI("SetDefaultDataSimPlugin OnGetPolicy success.");
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS

