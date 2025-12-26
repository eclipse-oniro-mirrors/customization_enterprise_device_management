/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "key_code.h"

#include <fcntl.h>
#include <unistd.h>

#include "securec.h"

#include "edm_constants.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
bool KeyEventHandle::WriteKeyCustomizationVector(MessageParcel &data,
    const std::vector<KeyCustomization> &keyCustomizations)
{
    if (!data.WriteInt32(keyCustomizations.size())) {
        return false;
    }

    for (const auto &keyCustomization : keyCustomizations) {
        if (!WriteKeyCustomization(data, keyCustomization)) {
            return false;
        }
    }
    return true;
}

bool KeyEventHandle::WriteKeyCustomization(MessageParcel &data, const KeyCustomization &keyCust)
{
    if (!data.WriteInt32(keyCust.keyCode)) {
        return false;
    }
    if (!data.WriteInt32(keyCust.keyPolicy)) {
        return false;
    }
    return true;
}

bool KeyEventHandle::ReadKeyCustomization(MessageParcel &data, KeyCustomization &keyCust)
{
    keyCust.keyCode = data.ReadInt32();
    keyCust.keyPolicy = data.ReadInt32();
    return true;
}

bool KeyEventHandle::ReadKeyCustomizationVector(MessageParcel &data,
    std::vector<KeyCustomization> &keyCustomizations)
{
    int32_t size = data.ReadInt32();
    keyCustomizations.clear();
    keyCustomizations.reserve(size);

    for (int32_t i = 0; i < size; i++) {
        KeyCustomization keyCust;
        if (!ReadKeyCustomization(data, keyCust)) {
            return false;
        }
        keyCustomizations.emplace_back(std::move(keyCust));
    }
    return true;
}
} // namespace EDM
} // namespace OHOS