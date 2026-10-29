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

#ifndef INTERFACES_INNER_API_COMMON_INCLUDE_SMS_MESSAGE_INFO_H
#define INTERFACES_INNER_API_COMMON_INCLUDE_SMS_MESSAGE_INFO_H

#include <string>
#include <cstdint>

#include "message_parcel.h"

namespace OHOS {
namespace EDM {

class SmsMessageInfo : public Parcelable {
public:
    SmsMessageInfo() = default;
    ~SmsMessageInfo() = default;

    bool Marshalling(Parcel &parcel) const override;
    static SmsMessageInfo *Unmarshalling(Parcel &parcel);

    int32_t slotId = 0;
    std::string telephoneNumber;
    std::string content;
    int64_t timer = 0;
    bool isSender = false;
};

} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_COMMON_INCLUDE_SMS_MESSAGE_INFO_H
