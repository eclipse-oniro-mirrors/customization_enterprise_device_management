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
 
#include "manage_auto_start_app_info.h"
#include "parcel_macro.h"
#include "edm_log.h"
 
namespace OHOS {
namespace EDM {
const std::string SEPARATOR = "/";
bool ManageAutoStartAppInfo::Marshalling(MessageParcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, bundleName_);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, abilityName_);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, disallowModify_);
    return true;
}
 
bool ManageAutoStartAppInfo::Unmarshalling(MessageParcel &parcel, ManageAutoStartAppInfo &appInfo)
{
    std::string bundleName = parcel.ReadString();
    std::string abilityName = parcel.ReadString();
    bool disallowModify = parcel.ReadBool();
    appInfo.SetBundleName(bundleName);
    appInfo.SetAbilityName(abilityName);
    appInfo.SetDisallowModify(disallowModify);
    return true;
}
 
bool ManageAutoStartAppInfo::SetUniqueKey(const std::string &uniqueKey)
{
    size_t index = uniqueKey.find(SEPARATOR);
    if (index != uniqueKey.npos) {
        bundleName_ = uniqueKey.substr(0, index);
        abilityName_ = uniqueKey.substr(index + 1);
    } else {
        EDMLOGE("ManageAutoStartAppInfo SetUniqueKey parse auto start app want failed");
        return false;
    }
    return true;
}
 
void ManageAutoStartAppInfo::SetBundleName(const std::string &bundleName)
{
    bundleName_ = bundleName;
}
 
void ManageAutoStartAppInfo::SetAbilityName(const std::string &abilityName)
{
    abilityName_ = abilityName;
}
 
void ManageAutoStartAppInfo::SetDisallowModify(bool disallowModify)
{
    disallowModify_ = disallowModify;
}
 
std::string ManageAutoStartAppInfo::GetBundleName() const
{
    return bundleName_;
}
 
std::string ManageAutoStartAppInfo::GetAbilityName() const
{
    return abilityName_;
}
 
bool ManageAutoStartAppInfo::GetDisallowModify() const
{
    return disallowModify_;
}
} // namespace EDM
} // namespace OHOS