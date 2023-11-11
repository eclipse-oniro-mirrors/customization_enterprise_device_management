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

#include "enterprise_admin_connection.h"

#include "admin_manager.h"
#include "edm_log.h"
#include "enterprise_conn_manager.h"

namespace OHOS {
namespace EDM {
EnterpriseAdminConnection::~EnterpriseAdminConnection() {}

void EnterpriseAdminConnection::SetIsOnAdminEnabled(bool isOnAdminEnabled)
{
    isOnAdminEnabled_ = isOnAdminEnabled;
}

void EnterpriseAdminConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int32_t resultCode)
{
    EDMLOGI("EnterpriseAdminConnection OnAbilityConnectDone");
    proxy_ = (new (std::nothrow) EnterpriseAdminProxy(remoteObject));
    if (!proxy_) {
        EDMLOGE("EnterpriseAdminConnection get enterpriseAdminProxy failed.");
        return;
    }
    switch (code_) {
        case IEnterpriseAdmin::COMMAND_ON_ADMIN_ENABLED:
            if (isOnAdminEnabled_) {
                proxy_->OnAdminEnabled();
            }
            if (AdminManager::GetInstance()->IsSuperAdmin(want_.GetElement().GetBundleName())) {
                if (!deathRecipient_) {
                    deathRecipient_ = (new (std::nothrow) AbilityManagerDeathRecipient(this));
                }
                if (!deathRecipient_) {
                    EDMLOGE("EnterpriseAdminConnection get enterpriseAdminProxy failed.");
                    return;
                }
                proxy_->AddDeathRecipient(deathRecipient_);
            }
            break;
        case IEnterpriseAdmin::COMMAND_ON_ADMIN_DISABLED:
            proxy_->OnAdminDisabled();
            proxy_->RemoveDeathRecipient(deathRecipient_);
            break;
        default:
            return;
    }
    EDMLOGI("EnterpriseAdminConnection OnAbilityConnectDone over");
}

void EnterpriseAdminConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int32_t resultCode)
{
    EDMLOGI("EnterpriseAdminConnection OnAbilityDisconnectDone");
}
}  // namespace EDM
}  // namespace OHOS
