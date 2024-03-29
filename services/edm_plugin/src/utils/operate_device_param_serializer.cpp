/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "operate_device_param_serializer.h"

#include "message_parcel_utils.h"

namespace OHOS {
namespace EDM {

bool OperateDeviceParamSerializer::Deserialize(const std::string &jsonString, OperateDeviceParam &policy)
{
    return true;
}

bool OperateDeviceParamSerializer::Serialize(const OperateDeviceParam &policy, std::string &jsonString)
{
    return true;
}

bool OperateDeviceParamSerializer::GetPolicy(MessageParcel &data, OperateDeviceParam &result)
{
    MessageParcelUtils::ReadOperateDeviceParam(data, result);
    return true;
}

bool OperateDeviceParamSerializer::WritePolicy(MessageParcel &reply, OperateDeviceParam &result)
{
    MessageParcelUtils::WriteOperateDeviceParam(result, reply);
    return true;
}

bool OperateDeviceParamSerializer::MergePolicy(std::vector<OperateDeviceParam> &data, OperateDeviceParam &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS