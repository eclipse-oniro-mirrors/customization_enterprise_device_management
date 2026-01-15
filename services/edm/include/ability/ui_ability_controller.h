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

#ifndef SERVICES_EDM_INCLUDE_ABILITY_UI_ABILITY_CONTROLLER_H
#define SERVICES_EDM_INCLUDE_ABILITY_UI_ABILITY_CONTROLLER_H

#include "ability_controller.h"

namespace OHOS {
namespace EDM {
class UIAbilityController : public AbilityController {
public:
    UIAbilityController(const EdmAbilityInfo &abilityInfo):  AbilityController(abilityInfo) {}

    ErrCode StartAbilityByAdmin(const AAFwk::Want &want, int32_t userId) override;

    bool VerifyPermission(const std::string &callerName) override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_ABILITY_UI_ABILITY_CONTROLLER_H