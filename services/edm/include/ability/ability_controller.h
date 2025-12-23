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

#ifndef SERVICES_EDM_INCLUDE_ABILITY_ABILITY_CONTROLLER_H
#define SERVICES_EDM_INCLUDE_ABILITY_ABILITY_CONTROLLER_H

#include "want.h"

namespace OHOS {
namespace EDM {
enum class AbilityType {
    UNKNOWN = -1,
    UNSUPPORT = 0,
    UI = 1,
    APP_SERVICE = 2
};

struct EdmAbilityInfo {
    AbilityType type = AbilityType::UNKNOWN;
    std::vector<std::string> permissions;
    std::string bundleName;
    bool visible = false;

    EdmAbilityInfo(const std::string &name) : bundleName(name) {}
};

class AbilityController {
public:
    AbilityController(const EdmAbilityInfo &abilityInfo) : abilityInfo_(abilityInfo) {}

    virtual ~AbilityController() = default;

    virtual ErrCode StartAbilityByAdmin(const AAFwk::Want &want, int32_t userId);

    virtual bool VerifyPermission(const std::string &callerName);
protected:
    EdmAbilityInfo abilityInfo_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_ABILITY_ABILITY_CONTROLLER_H