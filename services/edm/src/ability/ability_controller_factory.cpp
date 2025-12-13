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

#include "ability_controller_factory.h"

#include "app_service_extension_controller.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "ui_ability_controller.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<IExternalManagerFactory> AbilityControllerFactory::factory_ =
    std::make_shared<ExternalManagerFactory>();

EdmAbilityInfo AbilityControllerFactory::GetAbilityInfo(const AAFwk::Want &want, int32_t userId)
{
    EdmAbilityInfo info(want.GetElement().GetBundleName());
    AppExecFwk::AbilityInfo abilityInfo;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    if (factory_->CreateBundleManager()->QueryAbilityInfo(want,
        AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION, userId, abilityInfo)) {
        info.visible = abilityInfo.visible;
        info.type = abilityInfo.type == AppExecFwk::AbilityType::PAGE ? AbilityType::UI : AbilityType::UNSUPPORT;
        info.permissions = abilityInfo.permissions;
        return info;
    }

    if (factory_->CreateBundleManager()->QueryExtensionAbilityInfos(want,
        AppExecFwk::ExtensionAbilityInfoFlag::GET_EXTENSION_INFO_DEFAULT, userId, extensionInfos) &&
        !extensionInfos.empty()) {
        info.visible = extensionInfos[0].visible;
        info.type = extensionInfos[0].type == AppExecFwk::ExtensionAbilityType::APP_SERVICE ?
            AbilityType::APP_SERVICE : AbilityType::UNSUPPORT;
        return info;
    }
    return info;
}

std::shared_ptr<AbilityController> AbilityControllerFactory::CreateAbilityController(const AAFwk::Want &want,
    int32_t userId)
{
    // 校验want不能为空，避免隐式want
    if (want.GetElement().GetBundleName().empty() || want.GetElement().GetAbilityName().empty()) {
        EDMLOGE("empty BundleName or AbilityName.");
        return nullptr;
    }

    EdmAbilityInfo info = GetAbilityInfo(want, userId);
    if (info.type == AbilityType::UNKNOWN) {
        EDMLOGE("ability is not exist.");
        return nullptr;
    }

    if (info.type == AbilityType::UI) {
        return std::make_shared<UIAbilityController>(info);
    }

#ifdef FEATURE_PC_ONLY
    if (info.type == AbilityType::APP_SERVICE) {
        return std::make_shared<AppServiceExtensionController>(info);
    }
#endif

    return std::make_shared<AbilityController>(info);
}
} // namespace EDM
} // namespace OHOS