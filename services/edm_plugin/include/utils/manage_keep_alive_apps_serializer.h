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
 
#ifndef SERVICES_EDM_INCLUDE_UTILS_MANAGE_KEEP_ALIVE_APPS_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_MANAGE_KEEP_ALIVE_APPS_SERIALIZER_H
 
#include "edm_errors.h"
#include "ipolicy_serializer.h"
#include "singleton.h"
#include "manage_keep_alive_apps_info.h"
 
namespace OHOS {
namespace EDM {
 
/*
 * Policy data serializer of type std::vector<ManageKeepAliveAppInfo>.
 */
class ManageKeepAliveAppsSerializer : public IPolicySerializer<std::vector<ManageKeepAliveAppInfo>>,
    public DelayedSingleton<ManageKeepAliveAppsSerializer> {
public:
    std::vector<ManageKeepAliveAppInfo> SetUnionPolicyData(std::vector<ManageKeepAliveAppInfo> &data,
        std::vector<ManageKeepAliveAppInfo> &currentData);
 
    std::vector<ManageKeepAliveAppInfo> SetDifferencePolicyData(std::vector<ManageKeepAliveAppInfo> &data,
        std::vector<ManageKeepAliveAppInfo> &currentData);
    
    std::vector<ManageKeepAliveAppInfo> SetIntersectionPolicyData(std::vector<std::string> &data,
        std::vector<ManageKeepAliveAppInfo> &currentData);
    
    std::vector<ManageKeepAliveAppInfo> SetNeedRemoveMergePolicyData(std::vector<ManageKeepAliveAppInfo> &mergeData,
        std::vector<ManageKeepAliveAppInfo> &data);
 
    bool Deserialize(const std::string &policy, std::vector<ManageKeepAliveAppInfo> &dataObj) override;
 
    bool Serialize(const std::vector<ManageKeepAliveAppInfo> &dataObj, std::string &policy) override;
 
    bool GetPolicy(MessageParcel &data, std::vector<ManageKeepAliveAppInfo> &result) override;
 
    bool WritePolicy(MessageParcel &reply, std::vector<ManageKeepAliveAppInfo> &result) override;
 
    bool MergePolicy(std::vector<std::vector<ManageKeepAliveAppInfo>> &data,
        std::vector<ManageKeepAliveAppInfo> &result) override;
 
    bool UpdateByMergePolicy(std::vector<ManageKeepAliveAppInfo> &data, std::vector<ManageKeepAliveAppInfo> &mergeData);
};
} // namespace EDM
} // namespace OHOS
 
#endif //SERVICES_EDM_INCLUDE_UTILS_MANAGE_KEEP_ALIVE_APPS_SERIALIZER_H