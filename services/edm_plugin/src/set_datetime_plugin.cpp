/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "set_datetime_plugin.h"
#include "long_serializer.h"
#include "plugin_manager.h"
#include "policy_info.h"
#include "time_service_client.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(SetDateTimePlugin::GetPlugin());

void SetDateTimePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetDateTimePlugin, int64_t>> ptr)
{
    EDMLOGD("SetDateTimePlugin InitPlugin...");
    std::string policyName;
    POLICY_CODE_TO_NAME(SET_DATETIME, policyName);
    ptr->InitAttribute(SET_DATETIME, policyName, "ohos.permission.ENTERPRISE_SET_DATETIME", false);
    ptr->SetSerializer(LongSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetDateTimePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode SetDateTimePlugin::OnSetPolicy(int64_t &data)
{
    EDMLOGD("SetDateTimePlugin OnSetPolicy");
    MiscServices::TimeServiceClient::GetInstance()->SetTime(data);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
