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

#ifndef SERVICES_EDM_PLUGIN_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT_PLUGIN_H

#include "basic_bool_plugin.h"

namespace OHOS {
namespace EDM {
class InstallLocalEnterpriseAppEnabledForAccountPlugin : public BasicBoolPlugin {
public:
    InstallLocalEnterpriseAppEnabledForAccountPlugin();
private:
    ErrCode SetOtherModulePolicy(bool data, int32_t userId) override;
    void OnHandlePolicyDone(bool data, bool isGlobalChanged, int32_t userId) override;
    void OnAdminRemoveDone(int32_t userId) override;

public:
    void OnOtherServiceStart(int32_t systemAbilityId) override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT_PLUGIN_H
