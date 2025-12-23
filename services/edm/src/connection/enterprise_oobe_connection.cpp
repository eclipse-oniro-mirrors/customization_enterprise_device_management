/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "enterprise_oobe_connection.h"

#include "edm_log.h"
#include "enterprise_conn_manager.h"

namespace OHOS {
namespace EDM {
EnterpriseOobeConnection::~EnterpriseOobeConnection() {}

void EnterpriseOobeConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int32_t resultCode)
{
    EDMLOGI("EnterpriseOobeConnection OnAbilityConnectDone");
    proxy_ = (new (std::nothrow) EnterpriseAdminProxy(remoteObject));
    if (proxy_ == nullptr) {
        EDMLOGE("EnterpriseOobeConnection get enterpriseAdminProxy failed.");
        return;
    }
    switch (code_) {
        case IEnterpriseAdmin::COMMAND_ON_STARTUP_GUIDE_COMPLETED:
            proxy_->OnStartupGuideCompleted(type_);
            break;
        case IEnterpriseAdmin::COMMAND_ON_DEVICE_BOOT_COMPLETED:
            proxy_->OnDeviceBootCompleted();
            break;
        default:
            return;
    }
    
    EDMLOGI("EnterpriseOobeConnection OnAbilityConnectDone over");
}

void EnterpriseOobeConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element,
    int32_t resultCode)
{
    EDMLOGI("EnterpriseOobeConnection OnAbilityDisconnectDone");
}
}  // namespace EDM
}  // namespace OHOS