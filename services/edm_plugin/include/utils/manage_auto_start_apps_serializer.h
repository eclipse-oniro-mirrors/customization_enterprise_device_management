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
 
#ifndef SERVICES_EDM_INCLUDE_UTILS_MANAGE_AUTO_START_APPS_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_MANAGE_AUTO_START_APPS_SERIALIZER_H
 
#include "edm_errors.h"
#include "ipolicy_serializer.h"
#include "singleton.h"
#include "manage_auto_start_app_info.h"
 
namespace OHOS {
namespace EDM {
 
/*
 * Policy data serializer of type std::vector<ManageAutoStartAppInfo>.
 */
class ManageAutoStartAppsSerializer : public IPolicySerializer<std::vector<ManageAutoStartAppInfo>>,
    public DelayedSingleton<ManageAutoStartAppsSerializer> {
public:
    std::vector<ManageAutoStartAppInfo> SetUnionPolicyData(std::vector<ManageAutoStartAppInfo> &data,
        std::vector<ManageAutoStartAppInfo> &currentData);
 
    std::vector<ManageAutoStartAppInfo> SetDifferencePolicyData(std::vector<ManageAutoStartAppInfo> &data,
        std::vector<ManageAutoStartAppInfo> &currentData);
    
    std::vector<ManageAutoStartAppInfo> SetIntersectionPolicyData(std::vector<std::string> &data,
        std::vector<ManageAutoStartAppInfo> &currentData);
    
    std::vector<ManageAutoStartAppInfo> SetNeedRemoveMergePolicyData(std::vector<ManageAutoStartAppInfo> &mergeData,
        std::vector<ManageAutoStartAppInfo> &data);
 
    bool Deserialize(const std::string &policy, std::vector<ManageAutoStartAppInfo> &dataObj) override;
 
    bool Serialize(const std::vector<ManageAutoStartAppInfo> &dataObj, std::string &policy) override;
 
    bool GetPolicy(MessageParcel &data, std::vector<ManageAutoStartAppInfo> &result) override;
 
    bool WritePolicy(MessageParcel &reply, std::vector<ManageAutoStartAppInfo> &result) override;
 
    bool MergePolicy(std::vector<std::vector<ManageAutoStartAppInfo>> &data,
        std::vector<ManageAutoStartAppInfo> &result) override;
 
    bool UpdateByMergePolicy(std::vector<ManageAutoStartAppInfo> &data, std::vector<ManageAutoStartAppInfo> &mergeData);
};
} // namespace EDM
} // namespace OHOS
 
#endif //SERVICES_EDM_INCLUDE_UTILS_MANAGE_AUTO_START_APPS_SERIALIZER_H