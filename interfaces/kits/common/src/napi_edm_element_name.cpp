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

#include "napi_edm_element_name.h"

namespace OHOS {
namespace EDM {
void EdmElementName::SetIsHiddenStart(const bool isHiddenStart)
{
    isHiddenStart_ = isHiddenStart;
}

bool EdmElementName::GetIsHiddenStart() const
{
    return isHiddenStart_;
}

} // namespace EDM
} // namespace OHOS
