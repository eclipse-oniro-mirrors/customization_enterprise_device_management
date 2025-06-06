/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "enterprise_kiosk_connection.h"

#include "edm_log.h"
#include "enterprise_conn_manager.h"
#include "managed_event.h"

namespace OHOS {
namespace EDM {
EnterpriseKioskConnection::~EnterpriseKioskConnection() {}

void EnterpriseKioskConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int32_t resultCode)
{
    EDMLOGI("EnterpriseKioskConnection OnAbilityConnectDone");
    proxy_ = (new (std::nothrow) EnterpriseAdminProxy(remoteObject));
    if (proxy_ == nullptr) {
        EDMLOGI("EnterpriseKioskConnection get enterpriseAdminProxy failed.");
        return;
    }
    switch (code_) {
        case IEnterpriseAdmin::COMMAND_ON_KIOSK_MODE_ENTERING:
            proxy_->OnKioskModeEntering(bundleName_, accountId_);
            break;
        case IEnterpriseAdmin::COMMAND_ON_KIOSK_MODE_EXITING:
            proxy_->OnKioskModeExiting(bundleName_, accountId_);
            break;
        default:
            return;
    }
    EDMLOGI("EnterpriseKioskConnection OnAbilityConnectDone over");
}

void EnterpriseKioskConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int32_t resultCode)
{
    EDMLOGI("EnterpriseKioskConnection OnAbilityDisconnectDone");
}
}  // namespace EDM
}  // namespace OHOS
