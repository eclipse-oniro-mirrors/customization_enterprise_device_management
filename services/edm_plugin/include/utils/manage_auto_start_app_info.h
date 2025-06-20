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
 
#ifndef SERVICES_EDM_INCLUDE_UTILS_MANAGE_AUTO_START_APP_INFO_H
#define SERVICES_EDM_INCLUDE_UTILS_MANAGE_AUTO_START_APP_INFO_H
 
#include <string>
#include "message_parcel.h"
 
namespace OHOS {
namespace EDM {
 
class ManageAutoStartAppInfo {
public:
    bool Marshalling(MessageParcel &parcel) const;
    static bool Unmarshalling(MessageParcel &parcel, ManageAutoStartAppInfo &appInfo);
 
    void SetBundleName(const std::string &bundleName);
    void SetAbilityName(const std::string &abilityName);
    void SetDisallowModify(bool disallowModify);
    bool SetUniqueKey(const std::string &uniqueKey);
 
    std::string GetBundleName() const;
    std::string GetAbilityName() const;
    bool GetDisallowModify() const;
 
    std::string GetUniqueKey() const
    {
        return GetBundleName() + "/" + GetAbilityName();
    }
 
    bool operator<(const ManageAutoStartAppInfo &other) const
    {
        return (GetUniqueKey() == other.GetUniqueKey()) ?
            GetDisallowModify() < other.GetDisallowModify() :
            GetUniqueKey() < other.GetUniqueKey();
    }
 
private:
    std::string bundleName_;
    std::string abilityName_;
    bool disallowModify_ = false;
};
} // namespace EDM
} // namespace OHOS
 
#endif // SERVICES_EDM_INCLUDE_UTILS_MANAGE_AUTO_START_APP_INFO_H