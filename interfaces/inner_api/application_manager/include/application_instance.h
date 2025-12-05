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

#ifndef INTERFACES_INNER_API_APPLICATION_MANAGER_INCLUDE_APPLICATION_INSTANCE_H
#define INTERFACES_INNER_API_APPLICATION_MANAGER_INCLUDE_APPLICATION_INSTANCE_H

#include <message_parcel.h>
#include <string>

namespace OHOS {
namespace EDM {
struct ApplicationInstance {
    std::string appIdentifier;
    std::string bundleName;
    int32_t accountId;
    int32_t appIndex;

    bool operator<(const ApplicationInstance &other) const
    {
        if (appIdentifier != other.appIdentifier) {
            return appIdentifier < other.appIdentifier;
        }
        if (bundleName != other.bundleName) {
            return bundleName < other.bundleName;
        }
        if (accountId != other.accountId) {
            return accountId < other.accountId;
        }
        return appIndex < other.appIndex;
    }
};

class ApplicationInstanceHandle {
public:
    static bool WriteApplicationInstanceVector(MessageParcel &data,
        const std::vector<ApplicationInstance> freezeExemptedApps);
    static bool ReadApplicationInstanceVector(MessageParcel &reply,
        std::vector<ApplicationInstance> &freezeExemptedApps);
    static bool WriteApplicationInstance(MessageParcel &data, const ApplicationInstance appInstance);
    static bool ReadApplicationInstance(MessageParcel &reply, ApplicationInstance &appInstance);
    static bool GetBundleNameByAppId(ApplicationInstance &result);
    static bool GetBundleNameByAppId(const std::string appIdentifier, std::string &bundleName);
    static std::string GetAppIdentifierByBundleName(std::string bundleName, int32_t accountId);
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_APPLICATION_MANAGER_INCLUDE_APPLICATION_INSTANCE_H

