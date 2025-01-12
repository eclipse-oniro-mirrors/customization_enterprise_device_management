/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "disable_microphone_plugin.h"

#include "audio_system_manager.h"
#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableMicrophonePlugin::GetPlugin());
const std::string PARAM_EDM_MIC_DISABLE = "persist.edm.mic_disable";
constexpr int32_t AUDIO_SET_MICROPHONE_MUTE_SUCCESS = 0;
constexpr int32_t ERR_PRIVACY_POLICY_CHECK_FAILED = 13100019;
void DisableMicrophonePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableMicrophonePlugin, bool>> ptr)
{
    EDMLOGI("DisableMicrophonePlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS");
    typePermissions.emplace(IPlugin::PermissionType::BYOD_DEVICE_ADMIN,
        "ohos.permission.PERSONAL_MANAGE_RESTRICTIONS");
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_MICROPHONE, "disable_microphone", config, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableMicrophonePlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableMicrophonePlugin::OnAdminRemove);
    persistParam_ = "persist.edm.mic_disable";
}

ErrCode DisableMicrophonePlugin::SetOtherModulePolicy(bool isDisallow)
{
    EDMLOGI("DisableMicrophonePlugin OnSetPolicy...isDisallow = %{public}d", isDisallow);
    auto audioGroupManager = OHOS::AudioStandard::AudioSystemManager::GetInstance()
        ->GetGroupManager(OHOS::AudioStandard::DEFAULT_VOLUME_GROUP_ID);
    if (audioGroupManager == nullptr) {
        EDMLOGE("DisableMicrophonePlugin audioGroupManager null");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = audioGroupManager
        ->SetMicrophoneMutePersistent(isDisallow, OHOS::AudioStandard::PolicyType::EDM_POLICY_TYPE);
    if (ret == AUDIO_SET_MICROPHONE_MUTE_SUCCESS || (!isDisallow && ret == ERR_PRIVACY_POLICY_CHECK_FAILED)) {
        return ERR_OK;
    }
    EDMLOGE("DisableMicrophonePlugin SetOtherModulePolicy SetMicrophoneMutePersistent failed, %{public}d", ret);
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode DisableMicrophonePlugin::RemoveOtherModulePolicy()
{
    auto audioGroupManager = OHOS::AudioStandard::AudioSystemManager::GetInstance()
        ->GetGroupManager(OHOS::AudioStandard::DEFAULT_VOLUME_GROUP_ID);
    if (audioGroupManager == nullptr) {
        EDMLOGE("DisableMicrophonePlugin audioGroupManager null");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode ret =
        audioGroupManager->SetMicrophoneMutePersistent(false, OHOS::AudioStandard::PolicyType::EDM_POLICY_TYPE);
    if (ret == AUDIO_SET_MICROPHONE_MUTE_SUCCESS || ret == ERR_PRIVACY_POLICY_CHECK_FAILED) {
        return ERR_OK;
    }
    EDMLOGE("DisableMicrophonePlugin RemoveOtherModulePolicy SetMicrophoneMutePersistent failed, %{public}d", ret);
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}
} // namespace EDM
} // namespace OHOS
