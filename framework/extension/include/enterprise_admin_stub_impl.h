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

#ifndef FRAMEWORK_EXTENSION_INCLUDE_ENTERPRISE_ADMIN_STUB_IMPL_H
#define FRAMEWORK_EXTENSION_INCLUDE_ENTERPRISE_ADMIN_STUB_IMPL_H

#include <memory>

#include "enterprise_admin_stub.h"
#include "js_enterprise_admin_extension.h"
#include "policy_changed_event.h"

namespace OHOS {
namespace EDM {
class EnterpriseAdminStubImpl : public EnterpriseAdminStub {
public:
    explicit EnterpriseAdminStubImpl(const std::shared_ptr<JsEnterpriseAdminExtension>& extension)
        : extension_(extension) {}

    virtual ~EnterpriseAdminStubImpl() {}

    bool OnAdmin(uint32_t code) override;

    bool OnBundle(uint32_t code, const std::string &bundleName, int32_t accountId) override;

    bool OnApp(uint32_t code, const std::string &bundleName) override;

    bool OnSystemUpdate(const UpdateInfo &updateInfo) override;

    bool OnAccount(uint32_t code, const int32_t accountId) override;

    bool OnKioskMode(uint32_t code, const std::string &bundleName, int32_t accountId) override;

    bool OnMarketAppsInstallStatusChanged(const std::string &bundleName, int32_t status) override;

    bool OnDeviceAdmin(uint32_t code, const std::string &bundleName) override;

    bool OnLogCollected(bool isSuccess) override;

    bool OnKeyEvent(const std::string &event) override;

    bool OnStartupGuideCompleted(int32_t type) override;

    bool OnDeviceBootCompleted() override;

    bool OnAdminPolicyChanged(const PolicyChangedEvent &policyChangedEvent) override;
private:
    std::weak_ptr<JsEnterpriseAdminExtension> extension_;
};
} // namespace EDM
} // namespace OHOS
#endif // FRAMEWORK_EXTENSION_INCLUDE_ENTERPRISE_ADMIN_STUB_IMPL_H

