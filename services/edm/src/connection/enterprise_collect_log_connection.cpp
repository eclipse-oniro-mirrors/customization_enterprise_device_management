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

#include "enterprise_collect_log_connection.h"

#include "edm_log.h"
#include "enterprise_conn_manager.h"

namespace OHOS {
namespace EDM {
EnterpriseCollectLogConnection::~EnterpriseCollectLogConnection() {}

void EnterpriseCollectLogConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int32_t resultCode)
{
    EDMLOGI("EnterpriseCollectLogConnection OnAbilityConnectDone");
    proxy_ = (new (std::nothrow) EnterpriseAdminProxy(remoteObject));
    if (proxy_ == nullptr) {
        EDMLOGE("EnterpriseCollectLogConnection get enterpriseAdminProxy failed.");
        return;
    }
    proxy_->OnLogCollected(isSuccess_);
    EDMLOGI("EnterpriseCollectLogConnection OnAbilityConnectDone over");
}

void EnterpriseCollectLogConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element,
    int32_t resultCode)
{
    EDMLOGI("EnterpriseCollectLogConnection OnAbilityDisconnectDone");
}
}  // namespace EDM
}  // namespace OHOS