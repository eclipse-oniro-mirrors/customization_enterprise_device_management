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

#include "ability_manager_death_recipient.h"
#include "edm_log.h"
#include "enterprise_conn_manager.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
void AbilityManagerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& wptrDeath)
{
    EDMLOGI("ability manager service died, remove the proxy object");

    if (wptrDeath == nullptr) {
        EDMLOGE("wptrDeath is null");
        return;
    }

    sptr<IRemoteObject> object = wptrDeath.promote();
    if (object == nullptr) {
        EDMLOGE("object is null");
        return;
    }

    DelayedSingleton<EnterpriseConnManager>::GetInstance()->Clear();
}
}  // namespace EDM
}  // namespace OHOS