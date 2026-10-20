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

#include "patch_info.h"

#include "edm_constants.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
bool PatchDescriptionBody::Marshalling(Parcel &parcel) const
{
    return parcel.WriteString(title) && parcel.WriteStringVector(contents);
}

bool PatchDescriptionBody::Unmarshalling(Parcel &parcel, PatchDescriptionBody &body)
{
    return parcel.ReadString(body.title) && parcel.ReadStringVector(&body.contents);
}

bool PatchDescription::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteStringVector(headers)) {
        return false;
    }
    if (bodies.size() > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        EDMLOGE("PatchDescription bodies size over limit: %{public}zu", bodies.size());
        return false;
    }
    if (!parcel.WriteUint32(static_cast<uint32_t>(bodies.size()))) {
        return false;
    }
    for (const auto &body : bodies) {
        if (!body.Marshalling(parcel)) {
            return false;
        }
    }
    return true;
}

bool PatchDescription::Unmarshalling(Parcel &parcel, PatchDescription &description)
{
    if (!parcel.ReadStringVector(&description.headers)) {
        return false;
    }
    uint32_t size = 0;
    if (!parcel.ReadUint32(size)) {
        return false;
    }
    if (size > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        EDMLOGE("PatchDescription bodies size over limit: %{public}u", size);
        return false;
    }
    description.bodies.clear();
    description.bodies.reserve(size);
    for (uint32_t i = 0; i < size; ++i) {
        PatchDescriptionBody body;
        if (!PatchDescriptionBody::Unmarshalling(parcel, body)) {
            return false;
        }
        description.bodies.emplace_back(std::move(body));
    }
    return true;
}

bool PatchInfo::Marshalling(Parcel &parcel) const
{
    return parcel.WriteString(name) && parcel.WriteString(accountName) && parcel.WriteInt64(installTime) &&
        description.Marshalling(parcel);
}

bool PatchInfo::Unmarshalling(Parcel &parcel, PatchInfo &info)
{
    return parcel.ReadString(info.name) && parcel.ReadString(info.accountName) &&
        parcel.ReadInt64(info.installTime) && PatchDescription::Unmarshalling(parcel, info.description);
}
} // namespace EDM
} // namespace OHOS
