/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RESTRICTIONS_ANI_H
#define RESTRICTIONS_ANI_H

#include <ani.h>
#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {

class RestrictionsAni {
public:
    RestrictionsAni();
    ~RestrictionsAni() = default;
    static ani_status Init(ani_env* vm);
private:
    static void SetDisallowedPolicyForAccount(ani_env* env, ani_object admin,
        ani_string feature, ani_boolean disallow, ani_double accountId);
    static ani_boolean GetDisallowedPolicyForAccount(ani_env* env, ani_object admin,
        ani_string feature, ani_double accountId);
    static OHOS::ErrCode NativeGetDisallowedPolicyForAccount(bool hasAdmin, AppExecFwk::ElementName &elementName,
        std::uint32_t ipcCode, int32_t accountId, bool &disallow);
    static std::unordered_map<std::string, uint32_t> labelCodeMapForAccount;
};
} // namespace EDM
} // namespace OHOS
#endif
