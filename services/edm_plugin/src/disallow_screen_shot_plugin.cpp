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

#include "disallow_screen_shot_plugin.h"

#include "bool_serializer.h"
#include "display_manager.h"
#include "dm_common.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowScreenShotPlugin::GetPlugin());

void DisallowScreenShotPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisallowScreenShotPlugin, bool>> ptr)
{
    EDMLOGD("DisallowScreenShotPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOW_SCREEN_SHOT, "disallow_screen_shot",
        "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowScreenShotPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode DisallowScreenShotPlugin::OnSetPolicy(bool &isDisallow)
{
    EDMLOGI("DisallowScreenShotPlugin OnSetPolicy...isDisallow = %{public}d", isDisallow);
    auto &displayManager = OHOS::Rosen::DisplayManager::GetInstance();
    OHOS::Rosen::DMError ret = displayManager.DisableScreenshot(isDisallow);
    if (ret != OHOS::Rosen::DMError::DM_OK) {
        EDMLOGE("DisallowScreenShotPlugin displayManager DisableScreenshot result %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode DisallowScreenShotPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    bool isDisabled = false;
    pluginInstance_->serializer_->Deserialize(policyData, isDisabled);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isDisabled);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
