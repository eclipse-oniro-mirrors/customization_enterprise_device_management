/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "enterprise_market_connection.h"

#include "edm_log.h"
#include "enterprise_conn_manager.h"

namespace OHOS {
namespace EDM {
EnterpriseMarketConnection::~EnterpriseMarketConnection() {}

void EnterpriseMarketConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int32_t resultCode)
{
    EDMLOGI("EnterpriseMarketConnection OnAbilityConnectDone");
    proxy_ = (new (std::nothrow) EnterpriseAdminProxy(remoteObject));
    if (proxy_ == nullptr) {
        EDMLOGI("EnterpriseMarketConnection get enterpriseAdminProxy failed.");
        return;
    }
    proxy_->OnMarketAppsInstallStatusChanged(bundleName_, status_);
    EDMLOGI("EnterpriseMarketConnection OnAbilityConnectDone over");
}

void EnterpriseMarketConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int32_t resultCode)
{
    EDMLOGI("EnterpriseMarketConnection OnAbilityDisconnectDone");
}
}  // namespace EDM
}  // namespace OHOS
