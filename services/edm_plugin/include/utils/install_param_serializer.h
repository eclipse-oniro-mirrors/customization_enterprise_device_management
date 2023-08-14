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

#ifndef SERVICES_EDM_INCLUDE_UTILS_INSTALL_PARAM_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_INSTALL_PARAM_SERIALIZER_H

#include "ipolicy_serializer.h"
#include "json/json.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
struct InstallParam {
    std::vector<std::string> hapFilePaths;
    int32_t userId = 0;
    int32_t installFlag = 0;
};

/*
 * Policy data serializer of type int.
 */
class InstallParamSerializer : public IPolicySerializer<InstallParam>,
    public DelayedSingleton<InstallParamSerializer> {
public:
    bool Deserialize(const std::string &jsonString, InstallParam &dataObj) override;

    bool Serialize(const InstallParam &dataObj, std::string &jsonString) override;

    bool GetPolicy(MessageParcel &data, InstallParam &result) override;

    bool WritePolicy(MessageParcel &reply, InstallParam &result) override;

    bool MergePolicy(std::vector<InstallParam> &data, InstallParam &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_UTILS_INSTALL_PARAM_SERIALIZER_H
