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

#include "disable_camera_plugin.h"

#include "camera_manager.h"
#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const std::string PARAM_EDM_CAMERA_DISABLE = "persist.edm.camera_disable";
constexpr int32_t ERR_PRIVACY_POLICY_CHECK_FAILED = 13100019;
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableCameraPlugin::GetPlugin());

void DisableCameraPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableCameraPlugin, bool>> ptr)
{
    EDMLOGI("DisableCameraPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_CAMERA,
        "disable_camera", "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableCameraPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode DisableCameraPlugin::OnSetPolicy(bool &data)
{
    EDMLOGI("DisableCameraPlugin OnSetPolicy %{public}d", data);
    auto cameraManager = CameraStandard::CameraManager::GetInstance();
    if (cameraManager == nullptr) {
        EDMLOGE("DisableCameraPlugin CameraManager nullptr");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = cameraManager->MuteCameraPersist(CameraStandard::PolicyType::EDM, data);
    if (ret == ERR_OK || (!data && ret == ERR_PRIVACY_POLICY_CHECK_FAILED)) {
        std::string disableStr = data ? "true" : "false";
        system::SetParameter(PARAM_EDM_CAMERA_DISABLE, disableStr);
        return ERR_OK;
    }
    EDMLOGE("DisableCameraPlugin MuteCameraPersist ret %{public}d", ret);
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}
} // namespace EDM
} // namespace OHOS
