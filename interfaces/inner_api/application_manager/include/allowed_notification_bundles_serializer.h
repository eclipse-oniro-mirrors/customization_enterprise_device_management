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

#ifndef SERVICES_EDM_INCLUDE_UTILS_ALLOWED_NOTIFICATION_BUNDLES_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_ALLOWED_NOTIFICATION_BUNDLES_SERIALIZER_H

#include <vector>
#include "allowed_notification_bundles_type.h"
#include "ipolicy_serializer.h"
#include "plugin_singleton.h"

namespace OHOS {
namespace EDM {

class AllowedNotificationBundlesSerializer :
    public IPolicySerializer<std::vector<AllowedNotificationBundlesType>>,
    public DelayedSingleton<AllowedNotificationBundlesSerializer> {
public:
    bool Deserialize(const std::string &policy, std::vector<AllowedNotificationBundlesType> &dataObj) override;
    bool Serialize(const std::vector<AllowedNotificationBundlesType> &dataObj, std::string &policy) override;
    bool GetPolicy(MessageParcel &data, std::vector<AllowedNotificationBundlesType> &result) override;
    bool WritePolicy(MessageParcel &reply, std::vector<AllowedNotificationBundlesType> &result) override;
    bool MergePolicy(std::vector<std::vector<AllowedNotificationBundlesType>> &data,
        std::vector<AllowedNotificationBundlesType> &result) override;

private:
    bool CreateTrustListArray(cJSON* obj, const std::set<std::string> &trustList);
};

} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_UTILS_ALLOWED_NOTIFICATION_BUNDLES_SERIALIZER_H
