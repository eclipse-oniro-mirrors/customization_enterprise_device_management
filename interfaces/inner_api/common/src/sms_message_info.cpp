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

#include "sms_message_info.h"

namespace OHOS {
namespace EDM {

bool SmsMessageInfo::Marshalling(Parcel &parcel) const
{
    return parcel.WriteInt32(slotId) && parcel.WriteString(telephoneNumber) &&
           parcel.WriteString(content) && parcel.WriteInt64(timer) && parcel.WriteBool(isSender);
}

SmsMessageInfo *SmsMessageInfo::Unmarshalling(Parcel &parcel)
{
    SmsMessageInfo *info = new (std::nothrow) SmsMessageInfo();
    if (info == nullptr) {
        return nullptr;
    }
    bool ret = parcel.ReadInt32(info->slotId) && parcel.ReadString(info->telephoneNumber) &&
               parcel.ReadString(info->content) && parcel.ReadInt64(info->timer) &&
               parcel.ReadBool(info->isSender);
    if (!ret) {
        delete info;
        return nullptr;
    }
    return info;
}

} // namespace EDM
} // namespace OHOS
