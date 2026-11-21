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

#include "disallow_companion_ai_plugin.h"

#include "common_event_manager.h"
#include "common_event_support.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"
#include "want.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisallowCompanionAiPlugin>());

DisallowCompanionAiPlugin::DisallowCompanionAiPlugin()
{
    EDMLOGI("DisallowCompanionAiPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOW_COMPANION_AI;
    policyName_ = PolicyName::POLICY_DISALLOW_COMPANION_AI;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
    persistParam_ = "persist.edm.companion_ai_disable";
}

void DisallowCompanionAiPlugin::OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName,
    bool isGlobalChanged, int32_t userId)
{
    EDMLOGI("DisallowCompanionAiPlugin OnHandlePolicyDone isGlobalChanged:%{public}d", isGlobalChanged);
    if (isGlobalChanged) {
        NotifyCompanionAiChanged();
    }
}

void DisallowCompanionAiPlugin::NotifyCompanionAiChanged()
{
    EDMLOGD("DisallowCompanionAiPlugin NotifyCompanionAiChanged.");
    AAFwk::Want want;
    want.SetAction(EdmConstants::COMPANION_AI_CHANGED_EVENT);
    want.SetBundle(EdmConstants::SCENEBOARD_BUNDLE_NAME);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    if (!EventFwk::CommonEventManager::PublishCommonEvent(eventData)) {
        EDMLOGE("NotifyCompanionAiChanged failed.");
    }
}
} // namespace EDM
} // namespace OHOS
