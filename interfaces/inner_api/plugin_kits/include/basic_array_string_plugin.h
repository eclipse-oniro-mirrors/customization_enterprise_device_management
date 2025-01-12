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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_BSAIC_ARRAY_STRING_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_BSAIC_ARRAY_STRING_PLUGIN_H

#include <vector>

#include "edm_errors.h"
#include "message_parcel.h"

namespace OHOS {
namespace EDM {
class BasicArrayStringPlugin {
protected:
    virtual ErrCode OnBasicSetPolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
        std::vector<std::string> &mergeData, int32_t userId);
    virtual ErrCode BasicGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId);
    virtual ErrCode OnBasicRemovePolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
    std::vector<std::string> &mergeData, int32_t userId);
    virtual ErrCode OnBasicAdminRemove(const std::string &adminName, std::vector<std::string> &data,
        std::vector<std::string> &mergeData, int32_t userId);
    virtual ErrCode SetOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
        std::vector<std::string> &failedData);
    virtual ErrCode RemoveOtherModulePolicy(const std::vector<std::string> &data, int32_t userId,
        std::vector<std::string> &failedData);

    int32_t maxListSize_ = 0;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_BSAIC_ARRAY_STRING_PLUGIN_H
