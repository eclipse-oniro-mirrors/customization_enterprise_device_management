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

#ifndef COMMON_NATIVE_INCLUDE_HISYSEVENT_ADAPTER_H
#define COMMON_NATIVE_INCLUDE_HISYSEVENT_ADAPTER_H

#include <string>

namespace OHOS {
namespace EDM {
enum class ReportType {
    EDM_FUNC_FAILED = 0,
    EDM_FUNC_EVENT,
};
class HiSysEventAdapter {
public:
    static void ReportEdmEvent(ReportType reportType, const std::string &apiName, const std::string &msgInfo = "");
    static void ReportEdmEventManagerAdmin(const std::string &bundleName, const int32_t &action,
        const int32_t &adminType, const std::string &extraInfo = "");
};
} // namespace EDM
} // namespace OHOS
#endif // COMMON_NATIVE_INCLUDE_HISYSEVENT_ADAPTER_H
