/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "edm_ipc_interface_code.h"
#include "long_serializer.h"
#include "time_service_client.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(SetDateTimePlugin::GetPlugin());

void SetDateTimePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetDateTimePlugin, int64_t>> ptr)
{
    EDMLOGI("SetDateTimePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::SET_DATETIME, "set_datetime", "ohos.permission.ENTERPRISE_SET_DATETIME",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
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
