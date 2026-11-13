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

#include "notification_received_info.h"

namespace OHOS {
namespace EDM {
bool NotificationReceivedInfo::Marshalling(Parcel &parcel) const
{
    return parcel.WriteString(hashCode) && parcel.WriteString(bundleName) && parcel.WriteInt32(appIndex) &&
           parcel.WriteString(appName);
}

NotificationReceivedInfo *NotificationReceivedInfo::Unmarshalling(Parcel &parcel)
{
    NotificationReceivedInfo *info = new (std::nothrow) NotificationReceivedInfo();
    if (info == nullptr) {
        return nullptr;
    }
    bool ret = parcel.ReadString(info->hashCode) && parcel.ReadString(info->bundleName) &&
        parcel.ReadInt32(info->appIndex) && parcel.ReadString(info->appName);
    if (!ret) {
        delete info;
        return nullptr;
    }
    return info;
}
} // namespace EDM
} // namespace OHOS
