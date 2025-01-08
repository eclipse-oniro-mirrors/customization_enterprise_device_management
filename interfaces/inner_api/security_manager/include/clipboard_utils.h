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

#ifndef INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_CLIPBOARD_UTILS_H
#define INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_CLIPBOARD_UTILS_H

#include <map>

#include "clipboard_policy.h"
#include "edm_errors.h"

namespace OHOS {
namespace EDM {
class ClipboardUtils {
public:
    static ErrCode HandlePasteboardPolicy(std::map<int32_t, ClipboardPolicy> &data);
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_CLIPBOARD_UTILS_H