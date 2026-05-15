/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_ALLOWED_PERMISSION_BUNDLE_SERIALIZER_H
#define INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_ALLOWED_PERMISSION_BUNDLE_SERIALIZER_H

#include <map>
#include <vector>

#include "application_instance.h"
#include "ipolicy_serializer.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
class AllowedPermissionBundleSerializer :
    public IPolicySerializer<std::map<std::string, std::vector<ApplicationInstance>>>,
    public DelayedSingleton<AllowedPermissionBundleSerializer> {
public:
    std::map<std::string, std::vector<ApplicationInstance>> SetUnionPolicyData(
        std::map<std::string, std::vector<ApplicationInstance>> &data,
        std::map<std::string, std::vector<ApplicationInstance>> &currentData);

    std::map<std::string, std::vector<ApplicationInstance>> SetDifferencePolicyData(
        std::map<std::string, std::vector<ApplicationInstance>> &data,
        std::map<std::string, std::vector<ApplicationInstance>> &currentData);

    std::map<std::string, std::vector<ApplicationInstance>> SetIntersectionPolicyData(
        std::map<std::string, std::vector<ApplicationInstance>> &data,
        std::map<std::string, std::vector<ApplicationInstance>> &currentData);

    std::map<std::string, std::vector<ApplicationInstance>> SetNeedRemoveMergePolicyData(
        std::map<std::string, std::vector<ApplicationInstance>> &mergeData,
        std::map<std::string, std::vector<ApplicationInstance>> &data);

    std::string MakeKey(const ApplicationInstance &item);
    bool IsAppInList(const ApplicationInstance &app, const std::vector<ApplicationInstance> &appList);

private:
    std::vector<ApplicationInstance> GetAppsNotInList(
        const std::vector<ApplicationInstance> &sourceList,
        const std::vector<ApplicationInstance> &targetList);
    std::vector<ApplicationInstance> GetAppsInList(
        const std::vector<ApplicationInstance> &sourceList,
        const std::vector<ApplicationInstance> &targetList);
    void AddAppToMergedMap(const std::string &permissionName,
        const std::vector<ApplicationInstance> &appList,
        std::map<std::string, std::map<std::string, ApplicationInstance>> &mergedData);
    void MergePolicyDataIntoMap(
        const std::vector<std::map<std::string, std::vector<ApplicationInstance>>> &data,
        std::map<std::string, std::map<std::string, ApplicationInstance>> &mergedData);
    bool ParseAppItem(cJSON* appItem, ApplicationInstance &appInfo);
    bool ParsePermissionArray(cJSON* permissionItem, std::string &permissionName,
        std::vector<ApplicationInstance> &appList);
    cJSON* CreateAppObject(const ApplicationInstance &appInfo);
    bool SerializePermissionApps(const std::string &permissionName,
        const std::vector<ApplicationInstance> &appList, cJSON* root);

public:
    bool Deserialize(const std::string &policy,
        std::map<std::string, std::vector<ApplicationInstance>> &dataObj) override;

    bool Serialize(const std::map<std::string, std::vector<ApplicationInstance>> &dataObj,
        std::string &policy) override;

    bool GetPolicy(MessageParcel &data,
        std::map<std::string, std::vector<ApplicationInstance>> &result) override;

    bool WritePolicy(MessageParcel &reply,
        std::map<std::string, std::vector<ApplicationInstance>> &result) override;

    bool MergePolicy(std::vector<std::map<std::string, std::vector<ApplicationInstance>>> &data,
        std::map<std::string, std::vector<ApplicationInstance>> &result) override;
};

} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_ALLOWED_PERMISSION_BUNDLE_SERIALIZER_H