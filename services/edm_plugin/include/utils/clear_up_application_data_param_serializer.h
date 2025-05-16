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

#ifndef SERVICES_EDM_INCLUDE_UTILS_CLEAR_UP_APPLICATION_DATA_PARAM_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_CLEAR_UP_APPLICATION_DATA_PARAM_SERIALIZER_H

#include "clear_up_application_data_param.h"
#include "ipolicy_serializer.h"

namespace OHOS {
namespace EDM {

/*
 * Policy data serializer of type ClearUpApplicationDataParam.
 */
class ClearUpApplicationDataParamSerializer : public IPolicySerializer<ClearUpApplicationDataParam>,
                                              public DelayedSingleton<ClearUpApplicationDataParamSerializer> {
public:
    bool Deserialize(const std::string &policy, ClearUpApplicationDataParam &dataObj) override;

    bool Serialize(const ClearUpApplicationDataParam &dataObj, std::string &policy) override;

    bool GetPolicy(MessageParcel &data, ClearUpApplicationDataParam &result) override;

    bool WritePolicy(MessageParcel &reply, ClearUpApplicationDataParam &result) override;

    bool MergePolicy(std::vector<ClearUpApplicationDataParam> &data, ClearUpApplicationDataParam &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_UTILS_CLEAR_UP_APPLICATION_DATA_PARAM_SERIALIZER_H
