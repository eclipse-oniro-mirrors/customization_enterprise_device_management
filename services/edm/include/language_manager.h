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

#ifndef COMMON_NATIVE_INCLUDE_LANGUAGE_MANAGER_H
#define COMMON_NATIVE_INCLUDE_LANGUAGE_MANAGER_H

#include <string>

#include "resource_manager.h"

namespace OHOS {
namespace EDM {
class LanguageManager {
public:
    static std::string GetEnterpriseManagedTips();

private:
    static bool GetValueFromCloudSettings(std::string &result);
    static bool GetValueFromLocal(std::string &result);
    static std::string GetTargetLanguageValue(const std::string &jsonStr, const std::string &language);
    static bool InitResourceManager(std::shared_ptr<Global::Resource::ResourceManager> &resMgr);
    static void AddDataToResourceManager(std::shared_ptr<Global::Resource::ResourceManager> &resMgr);
    static bool GetDefaultLanguageResourcePath(std::string &path);
    static std::string GetEnterpriseName();
};
} // namespace EDM
} // namespace OHOS
#endif // COMMON_NATIVE_INCLUDE_LANGUAGE_MANAGER_H
