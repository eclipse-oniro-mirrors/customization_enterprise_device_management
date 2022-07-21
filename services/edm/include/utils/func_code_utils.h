/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_UTILS_FUNCCODE_UTILS_H
#define SERVICES_EDM_INCLUDE_UTILS_FUNCCODE_UTILS_H

#include <map>
#include <string>
#include <vector>
#include "func_code.h"

namespace OHOS {
namespace EDM {
class FuncCodeUtils {
public:
    static FuncFlag ConvertSystemFlag(std::uint32_t flag);

    static FuncFlag GetSystemFlag(std::uint32_t funcCode);

    static bool IsServiceFlag(std::uint32_t funcCode);

    static bool IsPolicyFlag(std::uint32_t funcCode);

    static FuncOperateType ConvertOperateType(std::uint32_t type);

    static FuncOperateType GetOperateType(std::uint32_t funcCode);

    static std::uint32_t GetPolicyCode(std::uint32_t funcCode);

    static std::uint32_t CreateFuncCode(std::uint32_t systemFlag, std::uint32_t operateType, std::uint32_t policyCode);

    static std::string PrintFuncCode(std::uint32_t funcCode);
};

class ArrayPolicyUtils {
public:
    static bool ArrayStringContains(const std::vector<std::string> &array, const std::string &findItem);

    static void RemovePolicy(std::vector<std::string> &removeData, std::vector<std::string> &currentData);

    static void RemovePolicy(std::vector<std::map<std::string, std::string>> &removeData,
        std::vector<std::map<std::string, std::string>> &currentData);

    static void U16StringToString(const std::vector<std::u16string> &u16stringArray,
        std::vector<std::string> &stringArray);

    static void StringToU16String(const std::vector<std::string> &stringArray,
        std::vector<std::u16string> &u16stringArray);
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_UTILS_FUNCCODE_UTILS_H
