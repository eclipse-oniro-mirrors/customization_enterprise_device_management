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

#include "volume_degree_plugin.h"

#include "audio_system_manager.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<VolumeDegreePlugin>());

constexpr int32_t STREAM_MUSIC = 1;
constexpr int32_t AUDIO_SET_VOLUME_SUCCESS = 0;

VolumeDegreePlugin::VolumeDegreePlugin()
{
    EDMLOGI("VolumeDegreePlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::VOLUME_DEGREE;
    policyName_ = PolicyName::POLICY_VOLUME_DEGREE;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

ErrCode VolumeDegreePlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("VolumeDegreePlugin OnHandlePolicy");
    auto operateType = static_cast<FuncOperateType>(FUNC_TO_OPERATE(funcCode));
    if (operateType != FuncOperateType::SET) {
        EDMLOGW("VolumeDegreePlugin unsupported operate type: %{public}d.", static_cast<int32_t>(operateType));
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    int32_t volumeType = 0;
    if (!data.ReadInt32(volumeType)) {
        EDMLOGE("VolumeDegreePlugin read volumeType failed.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    int32_t degree = 0;
    if (!data.ReadInt32(degree)) {
        EDMLOGE("VolumeDegreePlugin read degree failed.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (volumeType != STREAM_MUSIC) {
        EDMLOGE("VolumeDegreePlugin invalid volumeType: %{public}d.", volumeType);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    constexpr int32_t VOLUME_DEGREE_MIN = 0;
    constexpr int32_t VOLUME_DEGREE_MAX = 100;
    if (degree < VOLUME_DEGREE_MIN || degree > VOLUME_DEGREE_MAX) {
        EDMLOGE("VolumeDegreePlugin invalid degree: %{public}d.", degree);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    auto audioSystemManager = OHOS::AudioStandard::AudioSystemManager::GetInstance();
    if (audioSystemManager == nullptr) {
        EDMLOGE("VolumeDegreePlugin audioSystemManager is null.");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    int32_t ret = audioSystemManager->SetVolumeDegree(
        static_cast<OHOS::AudioStandard::AudioVolumeType>(volumeType), degree);
    OHOS::AudioStandard::AudioSystemManager::GetInstance()->CleanUpResource();
    if (ret != AUDIO_SET_VOLUME_SUCCESS) {
        EDMLOGE("VolumeDegreePlugin SetVolumeDegree failed, ret=%{public}d.", ret);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}

ErrCode VolumeDegreePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("VolumeDegreePlugin OnGetPolicy");
    int32_t volumeType = 0;
    if (!data.ReadInt32(volumeType)) {
        EDMLOGE("VolumeDegreePlugin read volumeType failed.");
        reply.WriteInt32(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (volumeType != STREAM_MUSIC) {
        EDMLOGE("VolumeDegreePlugin invalid volumeType: %{public}d.", volumeType);
        reply.WriteInt32(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    auto audioSystemManager = OHOS::AudioStandard::AudioSystemManager::GetInstance();
    if (audioSystemManager == nullptr) {
        EDMLOGE("VolumeDegreePlugin audioSystemManager is null.");
        reply.WriteInt32(EdmReturnErrCode::EXECUTE_TIME_OUT);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    int32_t degree = audioSystemManager->GetVolumeDegree(
        static_cast<OHOS::AudioStandard::AudioVolumeType>(volumeType));
    OHOS::AudioStandard::AudioSystemManager::GetInstance()->CleanUpResource();
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(degree);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS