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
 
#ifndef INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_PRINT_POLICY_UTIL_H
#define INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_PRINT_POLICY_UTIL_H
 
#include <string>
#include <vector>
 
#include "edm_errors.h"
 
namespace OHOS {
namespace EDM {
 
class PrintPolicyUtil {
public:
    static ErrCode GetPrintPolicy(int32_t userId, std::string &json);
 
private:
    static bool QueryDeviceLevelPolicy(std::vector<std::string> &ipAddresses);
    static bool QueryUserLevelPolicy(int32_t userId, std::vector<std::string> &ipAddresses);
    static std::string BuildPrintPolicyJson(const std::vector<std::string> &ipAddresses);
};
 
} // namespace EDM
} // namespace OHOS
 
#endif // INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_PRINT_POLICY_UTIL_H