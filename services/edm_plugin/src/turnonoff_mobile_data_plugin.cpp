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
#include "turnonoff_mobile_data_plugin.h"

#include "parameters.h"
#include "wifi_device.h"
#include "cellular_data_client.h"
#include "telephony_errors.h"
 
#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
 
namespace OHOS {
namespace EDM {
 
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(TurnOnOffMobileDataPlugin::GetPlugin());
const std::string PARAM_FORCE_OPEN_MOBILE_DATA = "persist.edm.mobile_data_policy";
 
void TurnOnOffMobileDataPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<TurnOnOffMobileDataPlugin, bool>> ptr)
{
    EDMLOGI("TurnOnMobileDataPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::TURNONOFF_MOBILE_DATA, "turnon_mobile_data",
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&TurnOnOffMobileDataPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&TurnOnOffMobileDataPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&TurnOnOffMobileDataPlugin::OnAdminRemove);
}
 
ErrCode TurnOnOffMobileDataPlugin::OnSetPolicy(bool &isForce)
{
    EDMLOGI("TurnOnMobileDataPlugin OnSetPolicy isForce %{public}d", isForce);
    int32_t ret = Telephony::CellularDataClient::GetInstance().EnableCellularData(true);
    if (ret != Telephony::TELEPHONY_ERR_SUCCESS) {
        EDMLOGE("TurnOnMobileDataPlugin:OnSetPolicy send request fail. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (!system::SetParameter(PARAM_FORCE_OPEN_MOBILE_DATA, isForce ? "force_open" : "none"))
    {
        EDMLOGE("TurnOnMobileDataPlugin:OnSetPolicy SetParameter fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode TurnOnOffMobileDataPlugin::OnRemovePolicy()
{
    EDMLOGI("TurnOnOffMobileDataPlugin OnRemovePolicy");
    if (!system::SetParameter(PARAM_FORCE_OPEN_MOBILE_DATA, "none")) {
        EDMLOGE("TurnOffMobileDataPlugin:OnSetPolicy SetParameter fail. ");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = Telephony::CellularDataClient::GetInstance().EnableCellularData(false);
    if (ret != Telephony::TELEPHONY_ERR_SUCCESS) {
        EDMLOGE("TurnOnMobileDataPlugin:OnSetPolicy send request fail. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    
    return ERR_OK;
}

ErrCode TurnOnOffMobileDataPlugin::OnAdminRemove(const std::string &adminName, bool &data, bool &mergeData, int32_t userId)
{
    EDMLOGI("TurnOnOffMobileDataPlugin OnAdminRemove adminName : %{public}s, data : %{public}d, userId : %{public}d",
        adminName.c_str(), data, userId);
    if (!mergeData) {
        if (!system::SetParameter(PARAM_FORCE_OPEN_MOBILE_DATA, "none")) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    
    return ERR_OK;
}

} // namespace EDM
} // namespace OHOS