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

#ifndef SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_BUNDLE_CONNECTION_H
#define SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_BUNDLE_CONNECTION_H

#include "ienterprise_connection.h"

namespace OHOS {
namespace EDM {
class EnterpriseBundleConnection : public IEnterpriseConnection {
public:
    EnterpriseBundleConnection(const AAFwk::Want &want, uint32_t code, uint32_t userId,
        const std::string &bundleName) : IEnterpriseConnection(want, code, userId), bundleName_(bundleName) {}
    
    ~EnterpriseBundleConnection() override;

    /**
     * OnAbilityConnectDone, Ability Manager Service notify caller ability the result of connect.
     *
     * @param element, Indicates elementName of service ability.
     * @param remoteObject, Indicates the session proxy of service ability.
     * @param resultCode, Returns ERR_OK on success, others on failure.
     */
    void OnAbilityConnectDone(const AppExecFwk::ElementName& element,
        const sptr<IRemoteObject>& remoteObject, int32_t resultCode) override;

    /**
     * OnAbilityDisconnectDone, Ability Manager Service notify caller ability the result of disconnect.
     *
     * @param element, Indicates elementName of service ability.
     * @param resultCode, Returns ERR_OK on success, others on failure.
     */
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int32_t resultCode) override;
private:
    std::string bundleName_;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_BUNDLE_CONNECTION_H