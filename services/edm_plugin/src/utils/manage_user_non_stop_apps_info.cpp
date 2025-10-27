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

#include "manage_user_non_stop_apps_info.h"
#include "parcel_macro.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
bool ManageUserNonStopAppInfo::Marshalling(MessageParcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, bundleName_);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, accountId_);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex_);
    return true;
}

bool ManageUserNonStopAppInfo::Unmarshalling(MessageParcel &parcel, ManageUserNonStopAppInfo &appInfo)
{
    std::string bundleName = parcel.ReadString();
    int32_t accountId = parcel.ReadInt32();
    int32_t appIndex = parcel.ReadInt32();
    appInfo.SetBundleName(bundleName);
    appInfo.SetAccountId(accountId);
    appInfo.SetAppIndex(appIndex);
    return true;
}

void ManageUserNonStopAppInfo::SetBundleName(std::string bundleName)
{
    bundleName_ = bundleName;
}

void ManageUserNonStopAppInfo::SetAccountId(int32_t accountId)
{
    accountId_ = accountId;
}

void ManageUserNonStopAppInfo::SetAppIndex(int32_t appIndex)
{
    appIndex_ = appIndex;
}

std::string ManageUserNonStopAppInfo::GetBundleName() const
{
    return bundleName_;
}

int32_t ManageUserNonStopAppInfo::GetAccountId() const
{
    return accountId_;
}

int32_t ManageUserNonStopAppInfo::GetAppIndex() const
{
    return appIndex_;
}
} // namespace EDM
} // namespace OHOS