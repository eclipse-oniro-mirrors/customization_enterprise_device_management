/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
 
#include "ota_update_nonce_plugin.h"
 
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "bool_serializer.h"
 
namespace OHOS {
namespace EDM {
 
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(OtaUpdateNoncePlugin::GetPlugin());
 
void OtaUpdateNoncePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<OtaUpdateNoncePlugin, bool>> ptr)
{
    EDMLOGI("OtaUpdateNoncePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::OTA_UPDATE_NONCE, PolicyName::POLICY_OTA_UPDATE_NONCE,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM, IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&OtaUpdateNoncePlugin::OnSetPolicy, FuncOperateType::SET);
}
 
ErrCode OtaUpdateNoncePlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
 
ErrCode OtaUpdateNoncePlugin::OnGetPolicy(
    std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS