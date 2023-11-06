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
#include "domain_filter_rule_serializer.h"

namespace OHOS {
namespace EDM {
bool DomainFilterRuleSerializer::Deserialize(const std::string &jsonString, IPTABLES::DomainFilterRuleParcel &dataObj)
{
    return true;
}

bool DomainFilterRuleSerializer::Serialize(const IPTABLES::DomainFilterRuleParcel &dataObj, std::string &jsonString)
{
    return true;
}

bool DomainFilterRuleSerializer::GetPolicy(MessageParcel &data, IPTABLES::DomainFilterRuleParcel &result)
{
    return IPTABLES::DomainFilterRuleParcel::Unmarshalling(data, result);
}

bool DomainFilterRuleSerializer::WritePolicy(MessageParcel &reply, IPTABLES::DomainFilterRuleParcel &result)
{
    return result.Marshalling(reply);
}

bool DomainFilterRuleSerializer::MergePolicy(std::vector<IPTABLES::DomainFilterRuleParcel> &data,
    IPTABLES::DomainFilterRuleParcel &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS