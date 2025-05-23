/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "clear_up_application_data_param_serializer.h"

#include "message_parcel_utils.h"

namespace OHOS {
namespace EDM {

bool ClearUpApplicationDataParamSerializer::Deserialize(
    const std::string &jsonString, ClearUpApplicationDataParam &policy)
{
    return true;
}

bool ClearUpApplicationDataParamSerializer::Serialize(
    const ClearUpApplicationDataParam &policy, std::string &jsonString)
{
    return true;
}

bool ClearUpApplicationDataParamSerializer::GetPolicy(MessageParcel &data, ClearUpApplicationDataParam &result)
{
    MessageParcelUtils::ReadClearUpApplicationDataParam(data, result);
    return true;
}

bool ClearUpApplicationDataParamSerializer::WritePolicy(MessageParcel &reply, ClearUpApplicationDataParam &result)
{
    MessageParcelUtils::WriteClearUpApplicationDataParam(result, reply);
    return true;
}

bool ClearUpApplicationDataParamSerializer::MergePolicy(
    std::vector<ClearUpApplicationDataParam> &data, ClearUpApplicationDataParam &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS