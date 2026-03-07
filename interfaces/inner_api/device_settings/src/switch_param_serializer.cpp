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
 
#include "switch_param_serializer.h"
 
namespace OHOS {
namespace EDM {
bool SwitchParamSerializer::Deserialize(const std::string &jsonString, SwitchParam &config)
{
    return true;
}
 
bool SwitchParamSerializer::Serialize(const SwitchParam &config, std::string &jsonString)
{
    return true;
}
 
bool SwitchParamSerializer::GetPolicy(MessageParcel &data, SwitchParam &result)
{
    int32_t key = data.ReadInt32();
    if (key >= static_cast<int32_t>(SwitchKey::NEARLINK) && key <= static_cast<int32_t>(SwitchKey::NFC)) {
        result.key = static_cast<SwitchKey>(key);
    }
    
    int32_t status = data.ReadInt32();
    if (status >= static_cast<int32_t>(SwitchStatus::ON) && status <= static_cast<int32_t>(SwitchStatus::FORCE_ON)) {
        result.status = static_cast<SwitchStatus>(status);
    }
    return true;
}
 
bool SwitchParamSerializer::WritePolicy(MessageParcel &reply, SwitchParam &result)
{
    return true;
}
 
bool SwitchParamSerializer::MergePolicy(std::vector<SwitchParam> &data, SwitchParam &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS