/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef COMMON_NATIVE_INCLUDE_EDM_UTILS_H
#define COMMON_NATIVE_INCLUDE_EDM_UTILS_H

#include <iostream>
#include <string>

#include "edm_errors.h"

namespace OHOS {
namespace EDM {
class EdmUtils {
public:
    static ErrCode ParseStringToInt(const std::string &str, int32_t &result);
    static ErrCode ParseStringToLong(const std::string &str, int64_t &result);
    static std::string Utf16ToUtf8(const std::u16string &str16);
    static void ClearString(std::string &str);
    static void ClearCharArray(char* &str, size_t size);
    static bool CheckRealPath(const std::string &path, const std::string &expectPath);
};
} // namespace EDM
} // namespace OHOS

#endif // COMMON_NATIVE_INCLUDE_EDM_UTILS_H
