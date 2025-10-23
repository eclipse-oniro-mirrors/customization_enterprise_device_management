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
 
#ifndef SERVICES_EDM_INCLUDE_UTILS_MANAGE_FREEZE_EXEMPTED_APP_INFO_H
#define SERVICES_EDM_INCLUDE_UTILS_MANAGE_FREEZE_EXEMPTED_APP_INFO_H

#include <string>
#include "message_parcel.h"
 
namespace OHOS {
namespace EDM {

class ManageFreezeExemptedAppInfo {
public:
    bool Marshalling(MessageParcel &parcel) const;
    static bool Unmarshalling(MessageParcel &parcel, ManageFreezeExemptedAppInfo &appInfo);

    void SetBundleName(std::string bundleName);
    void SetAccountId(int32_t accountId);
    void SetAppIndex(int32_t appIndex);

    std::string GetBundleName() const;
    int32_t GetAccountId() const;
    int32_t GetAppIndex() const;

    bool operator<(const ManageFreezeExemptedAppInfo &other) const
    {
        if (GetBundleName() != other.GetBundleName()) {
            return GetBundleName() < other.GetBundleName();
        }
        if (GetAccountId() != other.GetAccountId()) {
            return GetAccountId() < other.GetAccountId();
        }
        return GetAppIndex() < other.GetAppIndex();
    }
 
private:
    std::string bundleName_;
    int32_t accountId_;
    int32_t appIndex_;
};
} // namespace EDM
} // namespace OHOS
 
#endif // SERVICES_EDM_INCLUDE_UTILS_MANAGE_FREEZE_EXEMPTED_APP_INFO_H