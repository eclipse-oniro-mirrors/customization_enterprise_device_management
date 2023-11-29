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

#include "disallow_microphone_plugin.h"

#include "bool_serializer.h"
#include "dm_common.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"
#include "audio_system_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowMicrophonePlugin::GetPlugin());
const std::string PARAM_EDM_MIC_DISABLE = "persist.edm.edm_mic_disable";
void DisallowMicrophonePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisallowMicrophonePlugin, bool>> ptr)
{
    EDMLOGD("DisallowMicrophonePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOW_MICROPHONE, "disallow_microphone",
        "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowMicrophonePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode DisallowMicrophonePlugin::OnSetPolicy(bool &isDisallow)
{
    EDMLOGI("DisallowMicrophonePlugin OnSetPolicy...isDisallow = %{public}d", isDisallow);
    if (isDisallow) {
        auto audioSystemManager = OHOS::AudioStandard::AudioSystemManager::GetInstance();
        int32_t ret = audioSystemManager->SetMicrophoneMute(isDisallow);
        if (ret != ERR_OK) {
            EDMLOGE("DisallowMicrophonePlugin displayManager DisableMicrophone result %{public}d", ret);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        system::SetParameter(PARAM_EDM_MIC_DISABLE, "true");
    } else {
    	system::SetParameter(PARAM_EDM_MIC_DISABLE, "false");
    }
    return ERR_OK;
}

ErrCode DisallowMicrophonePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("DisallowMicrophonePlugin OnGetPolicy");
    std::string res = system::GetParameter(PARAM_EDM_MIC_DISABLE, "");
    EDMLOGI("DisallowMicrophonePlugin OnGetPolicy res = %{public}s", res.c_str());
    if (res == "true") {
        reply.WriteInt32(ERR_OK);
        reply.WriteBool(true);
    } else if (res == "false") {
        reply.WriteInt32(ERR_OK);
        reply.WriteInt32(false);
    } else {
        EDMLOGD("DisallowMicrophonePlugin get policy illegal. Value = %{public}s.", res.c_str());
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
	return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
