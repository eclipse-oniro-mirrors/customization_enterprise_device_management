/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "ent_info.h"
#include "edm_log.h"
#include "string_ex.h"
#include "parcel_macro.h"

namespace OHOS {
namespace EDM {
EntInfo::EntInfo(const std::string &enterpriseName, const std::string &description)
    : enterpriseName(enterpriseName), description(description)
{
    EDMLOGD("ent info instance is created with parameters");
}

EntInfo::EntInfo()
{
    EDMLOGD("ent info instance is created without parameter");
}

EntInfo::~EntInfo()
{
    EDMLOGD("ent info instance is destroyed");
}

bool EntInfo::Marshalling(MessageParcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, enterpriseName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, description);
    return true;
}

bool EntInfo::Unmarshalling(MessageParcel &parcel, EntInfo &entInfo)
{
    return entInfo.ReadFromParcel(parcel);
}

bool EntInfo::ReadFromParcel(MessageParcel &parcel)
{
    enterpriseName = parcel.ReadString();
    description = parcel.ReadString();
    return true;
}
} // namespace EDM
} // namespace OHOS
