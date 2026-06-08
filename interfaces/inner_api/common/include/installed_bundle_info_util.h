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

#ifndef INTERFACES_INNER_API_COMMON_INCLUDE_INSTALLED_BUNDLE_INFO_UTIL_H
#define INTERFACES_INNER_API_COMMON_INCLUDE_INSTALLED_BUNDLE_INFO_UTIL_H

#include <mutex>
#include <string>
#include <vector>

#include "iedm_timer_manager.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
enum class InstalledBundleType : int32_t {
    AG = 0,
    NORMAL = 1,
    MDM = 2
};

struct InstalledBundleInfo {
    std::string mdmName;
    std::string installedName;
    InstalledBundleType installedType;
    int64_t installedTime;
};

class InstalledBundleInfoUtil : public DelayedSingleton<InstalledBundleInfoUtil> {
public:
    InstalledBundleInfoUtil() = default;
    ~InstalledBundleInfoUtil() = default;

    bool AddInstalledBundleInfo(const std::string &mdmName, const std::string &installedName,
        InstalledBundleType installedType);
    size_t GetInstalledBundleInfoCount();
    bool HasInstalledBundleInfo();
    void ScheduleReportIfNeeded();
    void ReportAndClear();

private:
    bool LoadFromFile(std::vector<InstalledBundleInfo> &infoList);
    bool SaveToFile(const std::vector<InstalledBundleInfo> &infoList);
    bool EnsureFileExists();
    std::string SerializeToJson(const std::vector<InstalledBundleInfo> &infoList);
    bool ClearInstalledBundleInfoLocked();
    bool SwapAndClearLocked(std::vector<InstalledBundleInfo> &outList);
    bool RestoreToFileLocked(const std::vector<InstalledBundleInfo> &savedList);
    void ReportAndClearLocked(std::unique_lock<std::mutex> &lock);

    std::mutex fileMutex_;
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_COMMON_INCLUDE_INSTALLED_BUNDLE_INFO_UTIL_H