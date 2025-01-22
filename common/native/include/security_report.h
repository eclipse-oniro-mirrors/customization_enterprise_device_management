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

#ifndef COMMON_NATIVE_INCLUDE_SECURITY_REPORT_H
#define COMMON_NATIVE_INCLUDE_SECURITY_REPORT_H

#include <string>
#include "func_code.h"

namespace OHOS {
namespace EDM {
struct ReportInfo {
    FuncOperateType operateType_;
    int32_t subType_; // reserved
    std::string policyName_;
    std::string label_; // reserved
    std::string outcome_;
    std::string extra_;  // reserved

    ReportInfo(FuncOperateType operateType, const std::string &policyName, const std::string &outcome)
    {
        operateType_ = operateType;
        subType_ = 0;
        policyName_ = policyName;
        label_ = "";
        outcome_ = outcome;
        extra_ = "";
    };
};

class SecurityReport {
public:
    static void ReportSecurityInfo(const std::string &bundleName, const std::string &abilityName,
        const ReportInfo &reportInfo, bool isAsync);
};
} // namespace EDM
} // namespace OHOS

#endif // COMMON_NATIVE_INCLUDE_SECURITY_REPORT_H