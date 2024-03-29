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

#ifndef SERVICES_EDM_INCLUDE_UTILS_OPERATE_DEVICE_PARAM_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_OPERATE_DEVICE_PARAM_SERIALIZER_H

#include "ipolicy_serializer.h"
#include "operate_device_param.h"

namespace OHOS {
namespace EDM {

/*
 * Policy data serializer of type OperateDeviceParam.
 */
class OperateDeviceParamSerializer : public IPolicySerializer<OperateDeviceParam>,
    public DelayedSingleton<OperateDeviceParamSerializer> {
public:
    bool Deserialize(const std::string &policy, OperateDeviceParam &dataObj) override;

    bool Serialize(const OperateDeviceParam &dataObj, std::string &policy) override;

    bool GetPolicy(MessageParcel &data, OperateDeviceParam &result) override;

    bool WritePolicy(MessageParcel &reply, OperateDeviceParam &result) override;

    bool MergePolicy(std::vector<OperateDeviceParam> &data, OperateDeviceParam &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_UTILS_OPERATE_DEVICE_PARAM_SERIALIZER_H
