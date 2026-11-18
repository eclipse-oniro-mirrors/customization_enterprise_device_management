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

#ifndef SERVICES_EDM_INCLUDE_EDM_POLICY_NOTIFICATION_H
#define SERVICES_EDM_INCLUDE_EDM_POLICY_NOTIFICATION_H

#include <string>

#include "edm_bundle_manager_impl.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_os_account_manager_impl.h"
#include "iextra_policy_notification.h"
#include "policy_changed_event.h"

namespace OHOS {
namespace EDM {

class ExtraPolicyNotification final: public IExtraPolicyNotification {
public:
    ErrCode Notify(const std::string &adminName, const int32_t userId, const bool isSuccess) override;
    ErrCode ReportKeyEvent(const std::string &adminName, const int32_t userId, const std::string &keyEvent) override;
    bool NotifyPolicyChanged(const std::string &interfaceName, const std::string &parameters) override;
    bool NotifyControlPanelRestrictedChanged() override;
private:
    ErrCode UnloadPlugin(uint32_t code);
    void NotifySubscriber(const std::string &bundleName, const std::string &abilityName,
        const PolicyChangedEvent &changedEvent, int32_t userId);
    std::shared_ptr<IEdmOsAccountManager> edmOsAccountManagerImpl_ = std::make_shared<EdmOsAccountManagerImpl>();
    std::shared_ptr<IEdmBundleManager> edmBundleManagerImpl_ = std::make_shared<EdmBundleManagerImpl>();
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_EDM_POLICY_NOTIFICATION_H