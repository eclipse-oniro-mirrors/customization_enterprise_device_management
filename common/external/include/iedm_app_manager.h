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

#ifndef COMMON_EXTERNAL_INCLUDE_IEDM_APP_MANAGER_H
#define COMMON_EXTERNAL_INCLUDE_IEDM_APP_MANAGER_H

#include "app_mgr_interface.h"

#include "edm_errors.h"

namespace OHOS {
namespace EDM {
class IEdmAppManager {
public:
    virtual ~IEdmAppManager() = default;
    virtual ErrCode RegisterApplicationStateObserver(const sptr<AppExecFwk::IApplicationStateObserver>& observer) = 0;
    virtual ErrCode UnregisterApplicationStateObserver(const sptr<AppExecFwk::IApplicationStateObserver>& observer) = 0;
};
} // namespace EDM
} // namespace OHOS

#endif // COMMON_EXTERNAL_INCLUDE_IEDM_BUNDLE_MANAGER_H