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
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(DisableMicrophonePlugin::GetPlugin());
const std::string PARAM_EDM_MIC_DISABLE = "persist.edm.mic_disable";
const int32_t AUDIO_SET_MICROPHONE_MUTE_SUCCESS = 0;
void DisableMicrophonePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableMicrophonePlugin, bool>> ptr)
{
    EDMLOGI("DisableMicrophonePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_MICROPHONE, "disable_microphone",
        "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableMicrophonePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode DisableMicrophonePlugin::OnSetPolicy(bool &isDisallow)
{
    EDMLOGI("DisableMicrophonePlugin OnSetPolicy...isDisallow = %{public}d", isDisallow);
    if (isDisallow) {
        auto audioSystemManager = OHOS::AudioStandard::AudioSystemManager::GetInstance();
        int32_t ret = audioSystemManager->SetMicrophoneMute(isDisallow);
        if (ret != AUDIO_SET_MICROPHONE_MUTE_SUCCESS) {
            EDMLOGE("DisableMicrophonePlugin DisableMicrophone result %{public}d", ret);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        system::SetParameter(PARAM_EDM_MIC_DISABLE, "true");
    } else {
        system::SetParameter(PARAM_EDM_MIC_DISABLE, "false");
    }
    return ERR_OK;
}

ErrCode DisableMicrophonePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    bool isMicDisabled = system::GetBoolParameter(PARAM_EDM_MIC_DISABLE, false);
    EDMLOGI("DisableMicrophonePlugin OnGetPolicy isMicDisabled = %{public}d", isMicDisabled);
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(isMicDisabled);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
