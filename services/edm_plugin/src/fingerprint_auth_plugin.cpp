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

#include "fingerprint_auth_plugin.h"

#include "bool_serializer.h"
#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const std::string PERSIST_FINGERPRINT_AUTH_CONTROL = "persist.useriam.enable.fingerprintauth";

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(FingerprintAuthPlugin::GetPlugin());

void FingerprintAuthPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<FingerprintAuthPlugin, bool>> ptr)
{
    EDMLOGD("FingerprintAuthPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::FINGER_PRINT_AUTH, "FINGER_PRINT_AUTH",
        "ohos.permission.MANAGE_ENTERPRISE_DEVICE_ADMIN", IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&FingerprintAuthPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode FingerprintAuthPlugin::OnSetPolicy(bool &data)
{
    EDMLOGI("FingerprintAuthPlugin OnSetPolicy %{public}d", data);
    std::string value = data ? "false" : "true";
    return system::SetParameter(PERSIST_FINGERPRINT_AUTH_CONTROL, value) ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode FingerprintAuthPlugin::OnGetPolicy(std::string &value, MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    EDMLOGI("FingerprintAuthPlugin OnGetPolicy");
    bool ret = system::GetBoolParameter(PERSIST_FINGERPRINT_AUTH_CONTROL, true);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(!ret);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
