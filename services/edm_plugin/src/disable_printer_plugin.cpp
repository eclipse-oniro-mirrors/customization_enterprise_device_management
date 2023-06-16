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

#include "disable_printer_plugin.h"

#include "bool_serializer.h"
#include "iplugin_manager.h"
#include "policy_info.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisablePrinterPlugin::GetPlugin());

void DisablePrinterPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisablePrinterPlugin, bool>> ptr)
{
    EDMLOGD("DisablePrinterPlugin InitPlugin...");
    std::string policyName;
    POLICY_CODE_TO_NAME(DISABLED_PRINTER, policyName);
    ptr->InitAttribute(DISABLED_PRINTER, policyName, "ohos.permission.ENTERPRISE_RESTRICT_POLICY",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisablePrinterPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode DisablePrinterPlugin::OnSetPolicy(bool &data)
{
    return ERR_OK;
}

ErrCode DisablePrinterPlugin::OnGetPolicy(std::string &policyData,
    MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    EDMLOGI("DisablePrinterPlugin OnGetPolicy %{public}s...", policyData.c_str());
    bool isDisabled = false;
    pluginInstance_->serializer_->Deserialize(policyData, isDisabled);
    EDMLOGI("DisablePrinterPlugin isDisabled= %{public}d...", isDisabled);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isDisabled);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
