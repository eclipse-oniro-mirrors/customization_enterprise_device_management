/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "disallow_mobile_data_plugin.h"

#include "cellular_data_client.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"
#include "parameters.h"
#include "telephony_errors.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisallowMobileDataPlugin>());
constexpr const char *PARAM_MOBILE_DATA_POLICY = "persist.edm.mobile_data_policy";
constexpr const char *MOBILE_DATA_NONE = "none";
constexpr const char *MOBILE_DATA_DISALLOW = "disallow";
constexpr const char *MOBILE_DATA_FORCE_OPEN = "force_open";

DisallowMobileDataPlugin::DisallowMobileDataPlugin()
{
    policyCode_ = EdmInterfaceCode::DISALLOWED_MOBILE_DATA;
    policyName_ = PolicyName::POLICY_DISALLOW_MOBILE_DATA;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode DisallowMobileDataPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("DisallowMobileDataPlugin::OnHandlePolicy start");
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    if (type != FuncOperateType::SET) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    const std::string flag = data.ReadString();
    if (flag.empty() || flag == EdmConstants::MobileData::DISALLOW_FLAG) {
        const bool isDisallow = data.ReadBool();
        EDMLOGI("DisallowMobileDataPlugin:ReadBool isDisallow:%{public}d", isDisallow);
        if (isDisallow) {
            if (!system::SetParameter(PARAM_MOBILE_DATA_POLICY, MOBILE_DATA_DISALLOW)) {
                EDMLOGE("DisallowMobileDataPlugin:OnSetPolicy SetParameter fail");
                return EdmReturnErrCode::SYSTEM_ABNORMALLY;
            }
            int32_t ret = Telephony::CellularDataClient::GetInstance().EnableCellularData(false);
            EDMLOGI("DisallowMobileDataPlugin:OnSetPolicy send request result:%{public}d", ret);
            if (ret != Telephony::TELEPHONY_ERR_SUCCESS) {
                EDMLOGE("DisallowMobileDataPlugin:OnSetPolicy send request fail. %{public}d", ret);
                return EdmReturnErrCode::SYSTEM_ABNORMALLY;
            }
            policyData.isChanged = true;
            policyData.mergePolicyData = "true";
            policyData.policyData = "true";
            return ERR_OK;
        }
        if (!system::SetParameter(PARAM_MOBILE_DATA_POLICY, MOBILE_DATA_NONE)) {
            EDMLOGE("DisallowMobileDataPlugin:OnSetPolicy SetParameter fail");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        policyData.isChanged = true;
        policyData.mergePolicyData = "false";
        policyData.policyData = "false";
        return ERR_OK;
    }
    if (flag == EdmConstants::MobileData::FORCE_FLAG) {
        return OnHandleForceOpen(data);
    }
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode DisallowMobileDataPlugin::OnHandleForceOpen(MessageParcel &data)
{
    const int32_t foceOpen = data.ReadInt32();
    EDMLOGI("DisallowMobileDataPlugin:ReadInt32 foceOpen:%{public}d", foceOpen);
    if (foceOpen != EdmConstants::MobileData::FORCE_OPEN) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string dataPolicy = system::GetParameter(PARAM_MOBILE_DATA_POLICY, "");
    if (dataPolicy == MOBILE_DATA_DISALLOW) {
        EDMLOGE("DisallowMobileDataPlugin::OnSetPolicy failed, because mobile data disallow");
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }
    if (!system::SetParameter(PARAM_MOBILE_DATA_POLICY, MOBILE_DATA_FORCE_OPEN)) {
        EDMLOGE("DisallowMobileDataPlugin:OnSetPolicy SetParameter fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = Telephony::CellularDataClient::GetInstance().EnableCellularData(true);
    EDMLOGI("DisallowMobileDataPlugin:OnSetPolicy send request result:%{public}d", ret);
    if (ret != Telephony::TELEPHONY_ERR_SUCCESS) {
        EDMLOGE("DisallowMobileDataPlugin:OnSetPolicy send request fail. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode DisallowMobileDataPlugin::OnAdminRemove(const std::string &adminName, const std::string &policyData,
    const std::string &mergeData, int32_t userId)
{
    EDMLOGI("TurnOnOffMobileDataPlugin OnAdminRemove adminName : %{public}s, policyData : %{public}s,"
        " userId : %{public}d", adminName.c_str(), policyData.c_str(), userId);
    if (!system::SetParameter(PARAM_MOBILE_DATA_POLICY, MOBILE_DATA_NONE)) {
        EDMLOGE("DisallowMobileDataPlugin:OnSetPolicy SetParameter fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
