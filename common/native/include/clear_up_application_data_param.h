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

#ifndef COMMON_NATIVE_INCLUDE_CLEAR_UP_APPLICATION_DATA_PARAM_H
#define COMMON_NATIVE_INCLUDE_CLEAR_UP_APPLICATION_DATA_PARAM_H

#include <string>

namespace OHOS {
namespace EDM {
struct ClearUpApplicationDataParam {
    std::string bundleName;
    int32_t appIndex;
    int32_t userId;
};
} // namespace EDM
} // namespace OHOS
#endif // COMMON_NATIVE_INCLUDE_CLEAR_UP_APPLICATION_DATA_PARAM_H