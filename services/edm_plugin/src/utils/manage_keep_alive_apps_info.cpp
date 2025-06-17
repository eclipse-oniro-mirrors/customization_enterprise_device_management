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

#include "manage_keep_alive_apps_info.h"
#include "parcel_macro.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
bool ManageKeepAliveAppInfo::Marshalling(MessageParcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, bundleName_);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, disallowModify_);
    return true;
}

bool ManageKeepAliveAppInfo::Unmarshalling(MessageParcel &parcel, ManageKeepAliveAppInfo &appInfo)
{
    std::string bundleName = parcel.ReadString();
    bool disallowModify = parcel.ReadBool();
    appInfo.SetBundleName(bundleName);
    appInfo.SetDisallowModify(disallowModify);
    return true;
}

void ManageKeepAliveAppInfo::SetBundleName(std::string bundleName)
{
    bundleName_ = bundleName;
}

void ManageKeepAliveAppInfo::SetDisallowModify(bool disallowModify)
{
    disallowModify_ = disallowModify;
}

std::string ManageKeepAliveAppInfo::GetBundleName() const
{
    return bundleName_;
}

bool ManageKeepAliveAppInfo::GetDisallowModify() const
{
    return disallowModify_;
}
} // namespace EDM
} // namespace OHOS