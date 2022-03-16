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

#include "func_code_utils.h"
#include <edm_log.h>
#include <sstream>
#include <string_ex.h>

namespace OHOS {
namespace EDM {
FuncFlag FuncCodeUtils::ConvertSystemFlag(std::uint32_t flag)
{
    FuncFlag result = FuncFlag::UNKNOWN;
    switch (flag) {
        case static_cast<std::uint32_t>(FuncFlag::SERVICE_FLAG):
        case static_cast<std::uint32_t>(FuncFlag::POLICY_FLAG):
            result = static_cast<FuncFlag>(flag);
            break;
        default:
            break;
    }
    return result;
}

FuncFlag FuncCodeUtils::GetSystemFlag(std::uint32_t funcCode)
{
    return ConvertSystemFlag(FUNC_TO_FLAG(funcCode));
}

FuncOperateType FuncCodeUtils::ConvertOperateType(std::uint32_t type)
{
    FuncOperateType result = FuncOperateType::UNKNOWN;
    switch (type) {
        case static_cast<std::uint32_t>(FuncOperateType::GET):
        case static_cast<std::uint32_t>(FuncOperateType::SET):
        case static_cast<std::uint32_t>(FuncOperateType::REMOVE):
            result = static_cast<FuncOperateType>(type);
            break;
        default:
            break;
    }
    return result;
}

FuncOperateType FuncCodeUtils::GetOperateType(std::uint32_t funcCode)
{
    return ConvertOperateType(FUNC_TO_OPERATE(funcCode));
}

std::uint32_t FuncCodeUtils::GetPolicyCode(std::uint32_t funcCode)
{
    return FUNC_TO_POLICY(funcCode);
}

std::uint32_t FuncCodeUtils::CreateFuncCode(std::uint32_t systemFlag, std::uint32_t operateType,
    std::uint32_t policyCode)
{
    return CREATE_FUNC_CODE(systemFlag, operateType, policyCode);
}

bool FuncCodeUtils::IsServiceFlag(std::uint32_t funcCode)
{
    return GetSystemFlag(funcCode) == FuncFlag::SERVICE_FLAG;
}

bool FuncCodeUtils::IsPolicyFlag(std::uint32_t funcCode)
{
    return GetSystemFlag(funcCode) == FuncFlag::POLICY_FLAG;
}

std::string FuncCodeUtils::PrintFuncCode(std::uint32_t funcCode)
{
    std::ostringstream os;
    os << (std::bitset<32>(funcCode)); // funcCode is 32 bits
    EDMLOGD("PrintFuncCode bitset: %{public}s", os.str().c_str());
    return os.str();
}

bool ArrayPolicyUtils::ArrayStringContains(const std::vector<std::string> &array, const std::string &findItem)
{
    return std::any_of(array.begin(), array.end(), [&findItem](const std::string &item) { return item == findItem; });
}

void ArrayPolicyUtils::RemovePolicy(std::vector<std::string> &removeData, std::vector<std::string> &currentData)
{
    auto it = currentData.begin();
    while (it != currentData.end()) {
        if (ArrayStringContains(removeData, *it)) {
            it = currentData.erase(it);
        } else {
            it++;
        }
    }
}

void ArrayPolicyUtils::U16StringToString(const std::vector<std::u16string> &u16stringArray,
    std::vector<std::string> &stringArray)
{
    for (const std::u16string &item : u16stringArray) {
        stringArray.push_back(Str16ToStr8(item));
    }
}

void ArrayPolicyUtils::StringToU16String(const std::vector<std::string> &stringArray,
    std::vector<std::u16string> &u16stringArray)
{
    for (const std::string &item : stringArray) {
        u16stringArray.push_back(Str8ToStr16(item));
    }
}

void ArrayPolicyUtils::RemovePolicy(std::vector<std::map<std::string, std::string>> &removeData,
    std::vector<std::map<std::string, std::string>> &currentData)
{
    auto it = currentData.begin();
    while (it != currentData.end()) {
        bool contains = std::any_of(removeData.begin(), removeData.end(),
            [&it](const std::map<std::string, std::string> &item) { return item == *it; });
        if (contains) {
            it = currentData.erase(it);
        } else {
            it++;
        }
    }
}
} // namespace EDM
} // namespace OHOS