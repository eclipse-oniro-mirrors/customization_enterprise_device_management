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

#include "optimization_battery_exclusion_apps_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "array_string_serializer.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(OptimizationBatteryExclusionAppsPlugin::GetPlugin());

void OptimizationBatteryExclusionAppsPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<OptimizationBatteryExclusionAppsPlugin, std::vector<std::string>>> ptr)
{
    EDMLOGI("OptimizationBatteryExclusionAppsPlugin::InitPlugin start");

    ptr->InitAttribute(EdmInterfaceCode::OPTIMIZATION_BATTERY_EXCLUSION_APPS,
        PolicyName::POLICY_OPTIMIZATION_BATTERY_EXCLUSION_APPS,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(
        &OptimizationBatteryExclusionAppsPlugin::OnBasicSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(
        &OptimizationBatteryExclusionAppsPlugin::OnBasicRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(
        &OptimizationBatteryExclusionAppsPlugin::OnBasicAdminRemove);
    maxListSize_ = EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE;
    overMaxReturnErrCode_ = EdmReturnErrCode::POLICY_LIST_OVER_SIZE;
}
} // namespace EDM
} // namespace OHOS
