/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_CONNECTION_CALLBACK_H
#define SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_CONNECTION_CALLBACK_H

#include "ability_connect_callback_stub.h"

namespace OHOS {
namespace EDM {

class EnterpriseConnectionCallback : public AAFwk::AbilityConnectionStub {
public:
    EnterpriseConnectionCallback(const std::string& bundleName, int32_t userId);
    virtual ~EnterpriseConnectionCallback() = default;

    void OnAbilityConnectDone(const AppExecFwk::ElementName& element,
        const sptr<IRemoteObject>& remoteObject, int32_t resultCode) override;

    void OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int32_t resultCode) override;

private:
#if defined(FEATURE_PC_ONLY) && defined(LOG_SERVICE_PLUGIN_EDM_ENABLE)
    void CreateLogDirIfNeed(const std::string &bundleName, int32_t userId);
#endif
    std::string bundleName_;
    int32_t userId_;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_CONNECTION_CALLBACK_H
