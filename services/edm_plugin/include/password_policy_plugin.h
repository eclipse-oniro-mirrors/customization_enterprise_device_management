/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_PASSWORD_POLICY_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_PASSWORD_POLICY_PLUGIN_H

#include "plugin_singleton.h"
#include "password_policy_serializer.h"

namespace OHOS {
namespace EDM {
class PasswordPolicyPlugin : public PluginSingleton<PasswordPolicyPlugin, PasswordPolicy> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<PasswordPolicyPlugin, PasswordPolicy>> ptr) override;

    ErrCode OnSetPolicy(PasswordPolicy &policy, PasswordPolicy &currentData, PasswordPolicy &mergeData, int32_t userId);

    ErrCode OnAdminRemove(const std::string &adminName, PasswordPolicy &data, PasswordPolicy &mergeData,
        int32_t userId);

    void OnOtherServiceStart(int32_t systemAbilityId);

    void SetGlobalConfigParam(const PasswordPolicy &policy);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_PASSWORD_POLICY_PLUGIN_H