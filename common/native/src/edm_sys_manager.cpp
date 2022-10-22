/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "edm_sys_manager.h"
#include "edm_log.h"
#include "iservice_registry.h"

namespace OHOS {
namespace EDM {
sptr<IRemoteObject> EdmSysManager::GetRemoteObjectOfSystemAbility(int32_t systemAbilityId)
{
    EDMLOGD("EdmSysMgrManager GetRemoteObjectOfSystemAbility start");

    auto sysAbilityMgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sysAbilityMgr == nullptr) {
        EDMLOGE("EdmSysMgrManager GetRemoteObjectOfSystemAbility get system ability manager fail.");
        return nullptr;
    }
    return sysAbilityMgr->GetSystemAbility(systemAbilityId);
}
} // namespace EDM
} // namespace OHOS
