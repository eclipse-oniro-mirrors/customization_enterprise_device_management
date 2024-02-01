/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef COMMON_EXTERNAL_INCLUDE_EDM_BUNDLE_MANAGER_IMPL_MOCK_H
#define COMMON_EXTERNAL_INCLUDE_EDM_BUNDLE_MANAGER_IMPL_MOCK_H

#include <gmock/gmock.h>

#include "edm_errors.h"
#include "iedm_bundle_manager.h"

namespace OHOS {
namespace EDM {
class EdmBundleManagerImplMock : public IEdmBundleManager {
public:
    ~EdmBundleManagerImplMock() override = default;
    MOCK_METHOD(ErrCode, GetNameForUid, (int uid, std::string &name), (override));
    MOCK_METHOD(bool, QueryExtensionAbilityInfos, (const AAFwk::Want &want,
        const AppExecFwk::ExtensionAbilityType &extensionType, int32_t flag, int32_t userId,
        std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos), (override));
    MOCK_METHOD(bool, GetBundleInfo, (const std::string &bundleName, const AppExecFwk::BundleFlag flag,
        AppExecFwk::BundleInfo &bundleInfo, int32_t userId), (override));
};
} // namespace EDM
} // namespace OHOS

#endif // COMMON_EXTERNAL_INCLUDE_EDM_BUNDLE_MANAGER_IMPL_MOCK_H