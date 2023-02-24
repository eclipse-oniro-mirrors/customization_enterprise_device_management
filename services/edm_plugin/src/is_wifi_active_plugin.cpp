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

#include "is_wifi_active_plugin.h"
#include "bool_serializer.h"
#include "policy_info.h"
#include "wifi_device.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(IsWifiActivePlugin::GetPlugin());

void IsWifiActivePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<IsWifiActivePlugin, bool>> ptr)
{
    EDMLOGI("IsWifiActivePlugin InitPlugin...");
    std::string policyName;
    POLICY_CODE_TO_NAME(IS_WIFI_ACTIVE, policyName);
    ptr->InitAttribute(IS_WIFI_ACTIVE, policyName, "ohos.permission.ENTERPRISE_SET_WIFI", false);
    ptr->SetSerializer(BoolSerializer::GetInstance());
}

ErrCode IsWifiActivePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply)
{
    EDMLOGI("IsWifiActivePlugin OnGetPolicy.");
    bool isActive = IsWifiActive();
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isActive);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
