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

#include "password_policy_plugin.h"

#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "user_auth_client.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(PasswordPolicyPlugin::GetPlugin());

void PasswordPolicyPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<PasswordPolicyPlugin, PasswordPolicy>> ptr)
{
    EDMLOGI("PasswordPolicyPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::PASSWORD_POLICY,
        PolicyName::POLICY_PASSWORD_POLICY, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(PasswordSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&PasswordPolicyPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&PasswordPolicyPlugin::OnAdminRemove);
    ptr->SetOtherServiceStartListener(&PasswordPolicyPlugin::OnOtherServiceStart);
}

ErrCode PasswordPolicyPlugin::OnSetPolicy(PasswordPolicy &policy, PasswordPolicy &currentData,
    PasswordPolicy &mergeData, int32_t userId)
{
    EDMLOGI("PasswordPolicyPlugin OnSetPolicy...");
    if (!mergeData.complexityReg.empty() || mergeData.validityPeriod != 0 || !mergeData.additionalDescription.empty()) {
        EDMLOGE("LocationPolicyPlugin set location failed. Other admin has already set policies.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    SetGlobalConfigParam(policy);
    currentData = policy;
    mergeData = policy;
    return ERR_OK;
}

ErrCode PasswordPolicyPlugin::OnAdminRemove(const std::string &adminName, PasswordPolicy &data,
    PasswordPolicy &mergeData, int32_t userId)
{
    UserIam::UserAuth::GlobalConfigParam param;
    param.type = UserIam::UserAuth::GlobalConfigType::PIN_EXPIRED_PERIOD;
    param.value.pinExpiredPeriod = 0;
    param.authTypes.push_back(UserIam::UserAuth::AuthType::PIN);
    int32_t ret = UserIam::UserAuth::UserAuthClient::GetInstance().SetGlobalConfigParam(param);
    if (ret != ERR_OK) {
        EDMLOGW("PasswordPolicyPlugin SetGlobalConfigParam failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

void PasswordPolicyPlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    std::string policyData;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_PASSWORD_POLICY,
        policyData, EdmConstants::DEFAULT_USER_ID);
    auto serializer_ = PasswordSerializer::GetInstance();
    PasswordPolicy policy;
    serializer_->Deserialize(policyData, policy);
    SetGlobalConfigParam(policy);
}

void PasswordPolicyPlugin::SetGlobalConfigParam(const PasswordPolicy &policy)
{
    UserIam::UserAuth::GlobalConfigParam param;
    param.type = UserIam::UserAuth::GlobalConfigType::PIN_EXPIRED_PERIOD;
    param.authTypes.push_back(UserIam::UserAuth::AuthType::PIN);
    param.value.pinExpiredPeriod = policy.validityPeriod;
    int32_t ret = UserIam::UserAuth::UserAuthClient::GetInstance().SetGlobalConfigParam(param);
    if (ret != 0) {
        EDMLOGW("SetGlobalConfigParam SetPasswordPolicy Error");
    }
}
} // namespace EDM
} // namespace OHOS