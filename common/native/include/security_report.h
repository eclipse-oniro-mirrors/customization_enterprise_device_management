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

#include <string>

#ifndef COMMON_NATIVE_INCLUDE_SECURITY_REPORT_H
#define COMMON_NATIVE_INCLUDE_SECURITY_REPORT_H

namespace OHOS {
namespace EDM {
class SecurityReport {
public:
    static void ReportSecurityInfo(const std::string &bundleName, const std::string &abilityName,
        const std::string &policyName);
};
} // namespace EDM
} // namespace OHOS

#endif // COMMON_NATIVE_INCLUDE_SECURITY_REPORT_H