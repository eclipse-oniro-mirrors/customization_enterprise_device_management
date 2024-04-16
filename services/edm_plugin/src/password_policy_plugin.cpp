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
#include "plugin_manager.h"
#include "user_auth_client.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(PasswordPolicyPlugin::GetPlugin());

void PasswordPolicyPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<PasswordPolicyPlugin, PasswordPolicy>> ptr)
{
    EDMLOGI("PasswordPolicyPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::PASSWORD_POLICY,
        "password_policy", "ohos.permission.ENTERPRISE_MANAGE_SECURITY",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(PasswordSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&PasswordPolicyPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode PasswordPolicyPlugin::OnSetPolicy(PasswordPolicy &policy)
{
    EDMLOGI("PasswordPolicyPlugin OnSetPolicy...");
    UserIam::UserAuth::GlobalConfigParam param;
    param.type = UserIam::UserAuth::GlobalConfigType::PIN_EXPIRED_PERIOD;
    param.value.pinExpiredPeriod = policy.validityPeriod;
    int32_t ret = UserIam::UserAuth::UserAuthClient::GetInstance().SetGlobalConfigParam(param);
    if (ret != ERR_OK) {
        EDMLOGW("PasswordPolicyPlugin SetGlobalConfigParam failed");
    }
    return ERR_OK;
}

ErrCode PasswordPolicyPlugin::OnGetPolicy(std::string &policyData,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    PasswordPolicy policy;
    if (!pluginInstance_->serializer_->Deserialize(policyData, policy)) {
        EDMLOGD("PasswordPolicyPlugin Deserialize error!");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteString(policy.complexityReg);
    reply.WriteInt32(policy.validityPeriod);
    reply.WriteString(policy.additionalDescription);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS