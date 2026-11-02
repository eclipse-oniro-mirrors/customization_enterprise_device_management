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

#include "sms_receive_info.h"

namespace OHOS {
namespace EDM {

bool SmsReceiveInfo::Marshalling(Parcel &parcel) const
{
    return parcel.WriteInt32(slotId) && parcel.WriteString(telephoneNumber) &&
           parcel.WriteInt32(count) && parcel.WriteString(content);
}

SmsReceiveInfo *SmsReceiveInfo::Unmarshalling(Parcel &parcel)
{
    SmsReceiveInfo *info = new (std::nothrow) SmsReceiveInfo();
    if (info == nullptr) {
        return nullptr;
    }
    bool ret = parcel.ReadInt32(info->slotId) && parcel.ReadString(info->telephoneNumber) &&
               parcel.ReadInt32(info->count) && parcel.ReadString(info->content);
    if (!ret) {
        delete info;
        return nullptr;
    }
    return info;
}

} // namespace EDM
} // namespace OHOS
