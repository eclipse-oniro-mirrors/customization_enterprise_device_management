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

#include "edm_ipc_interface_code.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<TurnOnOffMobileDataPlugin>());
const std::string PARAM_FORCE_OPEN_MOBILE_DATA = "persist.edm.mobile_data_policy";


TurnOnOffMobileDataPlugin::TurnOnOffMobileDataPlugin()
{
    policyCode_ = EdmInterfaceCode::TURNONOFF_MOBILE_DATA;
    policyName_ = "turnon_mobile_data";
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

ErrCode TurnOnOffMobileDataPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    bool policy = data.ReadBool();
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    if (type == FuncOperateType::SET) {
        return OnSetPolicy(policy);
    }
    if (type == FuncOperateType::REMOVE) {
        return OnRemovePolicy();
    }
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode TurnOnOffMobileDataPlugin::OnSetPolicy(bool isForce)
{
    EDMLOGI("TurnOnOffMobileDataPlugin OnSetPolicy isForce %{public}d", isForce);
    std::string dataPolicy = system::GetParameter(PARAM_FORCE_OPEN_MOBILE_DATA, "");
    if (dataPolicy == "disallow") {
        EDMLOGE("TurnOnOffMobileDataPlugin::OnSetPolicy failed, because mobile data disallow");
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }
    if (!isForce && !system::SetParameter(PARAM_FORCE_OPEN_MOBILE_DATA, "none")) {
        EDMLOGE("TurnOnOffMobileDataPlugin:OnRemovePolicy SetParameter fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = Telephony::CellularDataClient::GetInstance().EnableCellularData(true);
    if (ret != Telephony::TELEPHONY_ERR_SUCCESS) {
        EDMLOGE("TurnOnOffMobileDataPlugin:OnSetPolicy send request fail. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode TurnOnOffMobileDataPlugin::OnRemovePolicy()
{
    EDMLOGI("TurnOnOffMobileDataPlugin OnRemovePolicy");
    std::string dataPolicy = system::GetParameter(PARAM_FORCE_OPEN_MOBILE_DATA, "");
    if (dataPolicy == "disallow") {
        EDMLOGE("TurnOnOffMobileDataPlugin::OnSetPolicy failed, because mobile data disallow");
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }
    if (!system::SetParameter(PARAM_FORCE_OPEN_MOBILE_DATA, "none")) {
        EDMLOGE("TurnOnOffMobileDataPlugin:OnRemovePolicy SetParameter fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = Telephony::CellularDataClient::GetInstance().EnableCellularData(false);
    if (ret != Telephony::TELEPHONY_ERR_SUCCESS) {
        EDMLOGE("TurnOnOffMobileDataPlugin:OnRemovePolicy send request fail. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

} // namespace EDM
} // namespace OHOS