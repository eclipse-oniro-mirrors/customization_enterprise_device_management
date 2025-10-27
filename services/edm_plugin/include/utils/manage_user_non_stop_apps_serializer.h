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
 
#ifndef SERVICES_EDM_INCLUDE_UTILS_MANAGE_USER_NON_STOP_APPS_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_MANAGE_USER_NON_STOP_APPS_SERIALIZER_H
 
#include "edm_errors.h"
#include "ipolicy_serializer.h"
#include "singleton.h"
#include "manage_user_non_stop_apps_info.h"
#include "application_instance.h"
 
namespace OHOS {
namespace EDM {
 
/*
 * Policy data serializer of type std::vector<ManageUserNonStopAppInfo>.
 */
class ManageUserNonStopAppsSerializer : public IPolicySerializer<std::vector<ManageUserNonStopAppInfo>>,
    public DelayedSingleton<ManageUserNonStopAppsSerializer> {
public:
    std::vector<ManageUserNonStopAppInfo> SetUnionPolicyData(std::vector<ManageUserNonStopAppInfo> &data,
        std::vector<ManageUserNonStopAppInfo> &currentData);
 
    std::vector<ManageUserNonStopAppInfo> SetDifferencePolicyData(std::vector<ManageUserNonStopAppInfo> &data,
        std::vector<ManageUserNonStopAppInfo> &currentData);
    
    std::vector<ManageUserNonStopAppInfo> SetIntersectionPolicyData(std::vector<ApplicationMsg> &data,
        std::vector<ManageUserNonStopAppInfo> &currentData);
    
    std::vector<ManageUserNonStopAppInfo> SetNeedRemoveMergePolicyData(std::vector<ManageUserNonStopAppInfo> &mergeData,
        std::vector<ManageUserNonStopAppInfo> &data);

    bool Deserialize(const std::string &policy, std::vector<ManageUserNonStopAppInfo> &dataObj) override;
 
    bool Serialize(const std::vector<ManageUserNonStopAppInfo> &dataObj, std::string &policy) override;
 
    bool GetPolicy(MessageParcel &data, std::vector<ManageUserNonStopAppInfo> &result) override;
 
    bool WritePolicy(MessageParcel &reply, std::vector<ManageUserNonStopAppInfo> &result) override;
 
    bool MergePolicy(std::vector<std::vector<ManageUserNonStopAppInfo>> &data,
        std::vector<ManageUserNonStopAppInfo> &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif //SERVICES_EDM_INCLUDE_UTILS_MANAGE_USER_NON_STOP_APPS_SERIALIZER_H