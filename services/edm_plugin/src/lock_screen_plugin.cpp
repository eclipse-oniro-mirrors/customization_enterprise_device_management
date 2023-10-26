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

#include "lock_screen_plugin.h"

#include "edm_ipc_interface_code.h"
#include "int_serializer.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(LockScreenPlugin::GetPlugin());

void LockScreenPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<LockScreenPlugin, int32_t>> ptr)
{
    EDMLOGD("LockScreenPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::LOCK_SCREEN, "lock_screen", "ohos.permission.ENTERPRISE_LOCK_DEVICE",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(IntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&LockScreenPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode LockScreenPlugin::OnSetPolicy(int32_t &data)
{
    EDMLOGD("LockScreenPlugin OnSetPolicy userId = %{public}d.", data);
    int32_t userId = data;
    ScreenLock::ScreenLockManager::GetInstance()->Lock(userId);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
