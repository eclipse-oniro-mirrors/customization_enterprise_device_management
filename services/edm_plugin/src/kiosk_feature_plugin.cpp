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

#include "kiosk_feature_plugin.h"

#include "array_int_serializer.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "kiosk_feature.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(KioskFeaturePlugin::GetPlugin());

void KioskFeaturePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<KioskFeaturePlugin, std::vector<int32_t>>> ptr)
{
    EDMLOGI("KioskFeaturePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::SET_KIOSK_FEATURE, PolicyName::POLICY_SET_KIOSK_FEATURE,
        EdmPermission::PERMISSION_ENTERPRISE_SET_KIOSK, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayIntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&KioskFeaturePlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&KioskFeaturePlugin::OnAdminRemove);
}

ErrCode KioskFeaturePlugin::OnSetPolicy(std::vector<int32_t> &data, std::vector<int32_t> &currentData,
    std::vector<int32_t> &mergeData, int32_t userId)
{
    EDMLOGW("KioskFeaturePlugin OnSetPolicy data size = %{public}zu", data.size());
    if (data.empty()) {
        EDMLOGW("KioskFeaturePlugin OnSetPolicy data is empty. reset to default features");
        SetDefaultKioskFeatures(false);
        return ERR_OK;
    }
    if (data.size() > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        EDMLOGE("KioskFeaturePlugin OnSetPolicy size is over limit");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    for (size_t i = 0; i < data.size(); i++) {
        ErrCode ret = SetSpecifiedKioskFeatures(data[i]);
        if (ret != ERR_OK) {
            return ret;
        }
    }
    currentData = data;
    mergeData = currentData;
    return ERR_OK;
}

void KioskFeaturePlugin::SetDefaultKioskFeatures(bool isDisallow)
{
    std::string value = isDisallow ? "true" : "false";
    system::SetParameter(EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_NOTIFICATION_CENTER, value);
    system::SetParameter(EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_CONTROL_CENTER, value);
    system::SetParameter(EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_GESTURE_CONTROL, value);
    system::SetParameter(EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_SIDE_DOCK, value);
}

ErrCode KioskFeaturePlugin::SetSpecifiedKioskFeatures(int32_t data)
{
    switch (data) {
        case static_cast<int32_t>(KioskFeature::ALLOW_NOTIFICATION_CENTER):
            system::SetParameter(EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_NOTIFICATION_CENTER,
                "true");
            break;
        case static_cast<int32_t>(KioskFeature::ALLOW_CONTROL_CENTER):
            system::SetParameter(EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_CONTROL_CENTER, "true");
            break;
        case static_cast<int32_t>(KioskFeature::ALLOW_GESTURE_CONTROL):
            system::SetParameter(EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_GESTURE_CONTROL, "true");
            break;
        case static_cast<int32_t>(KioskFeature::ALLOW_SIDE_DOCK):
            system::SetParameter(EdmConstants::ApplicationManager::PARAM_EDM_KIOSK_ALLOW_SIDE_DOCK, "true");
            break;
        default:
            EDMLOGE("KioskFeaturePlugin kiosk feature illegal. Value = %{public}d.", data);
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return ERR_OK;
}

ErrCode KioskFeaturePlugin::OnAdminRemove(const std::string &adminName, std::vector<int32_t> &policyData,
    std::vector<int32_t> &mergeData, int32_t userId)
{
    SetDefaultKioskFeatures(false);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
