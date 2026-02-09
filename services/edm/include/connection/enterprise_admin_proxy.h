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

#ifndef SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_ADMIN_PROXY_H
#define SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_ADMIN_PROXY_H

#include <iremote_proxy.h>

#include "ienterprise_admin.h"
#include "policy_struct.h"

namespace OHOS {
namespace EDM {
class EnterpriseAdminProxy : public IRemoteProxy<IEnterpriseAdmin> {
public:
    explicit EnterpriseAdminProxy(const sptr<IRemoteObject>& remote)
        : IRemoteProxy<IEnterpriseAdmin>(remote) {}

    virtual ~EnterpriseAdminProxy() {}

    void OnAdminEnabled() override;

    void OnAdminDisabled() override;

    void OnBundleAdded(const std::string &bundleName, int32_t accountId) override;

    void OnBundleRemoved(const std::string &bundleName, int32_t accountId) override;

    void OnAppStart(const std::string &bundleName) override;

    void OnAppStop(const std::string &bundleName) override;

    void OnSystemUpdate(const UpdateInfo &updateInfo) override;

    void OnAccountAdded(const int32_t accountId) override;

    void OnAccountSwitched(const int32_t accountId) override;

    void OnAccountRemoved(const int32_t accountId) override;

    void OnKioskModeEntering(const std::string &bundleName, int32_t accountId) override;

    void OnKioskModeExiting(const std::string &bundleName, int32_t accountId) override;

    void OnMarketAppsInstallStatusChanged(const std::string &bundleName, int32_t status) override;

    void OnDeviceAdminEnabled(const std::string &bundleName) override;

    void OnDeviceAdminDisabled(const std::string &bundleName) override;

    void OnLogCollected(bool isSuccess) override;

    void OnKeyEvent(const std::string &keyEvent) override;

    void OnStartupGuideCompleted(int32_t type) override;

    void OnDeviceBootCompleted() override;
private:
    void SendRequest(uint32_t code, MessageParcel &data);
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_CONNECTION_ENTERPRISE_ADMIN_PROXY_H
