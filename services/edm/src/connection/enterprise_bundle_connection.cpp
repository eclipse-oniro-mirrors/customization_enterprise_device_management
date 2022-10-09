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

#include "enterprise_bundle_connection.h"
#include "enterprise_conn_manager.h"
#include "managed_event.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace EDM {
EnterpriseBundleConnection::~EnterpriseBundleConnection() {}

void EnterpriseBundleConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int32_t resultCode)
{
    HILOG_INFO("EnterpriseBundleConnection OnAbilityConnectDone");
    proxy_ = (new (std::nothrow) EnterpriseAdminProxy(remoteObject));
    if (proxy_ == nullptr) {
        HILOG_INFO("EnterpriseBundleConnection get enterpriseAdminProxy failed.");
        return;
    }
    switch (code_) {
        case static_cast<uint32_t>(ManagedEvent::BUNDLE_ADDED):
            proxy_->OnBundleAdded(bundleName_);
            break;
        case static_cast<uint32_t>(ManagedEvent::BUNDLE_REMOVED):
            proxy_->OnBundleRemoved(bundleName_);
            break;
        default:
            return;
    }
    HILOG_INFO("EnterpriseBundleConnection OnAbilityConnectDone over");
}

void EnterpriseBundleConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int32_t resultCode)
{
    HILOG_INFO("EnterpriseBundleConnection OnAbilityDisconnectDone");
}
}  // namespace EDM
}  // namespace OHOS
