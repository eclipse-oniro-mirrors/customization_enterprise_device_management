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

#include "icallback_strategy.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
// Admin策略
void ICallbackStrategy::Execute(const sptr<EnterpriseAdminProxy>& proxy)
{
    if (proxy) {
        ExecuteImpl(proxy);
    } else {
        EDMLOGE("ICallbackStrategy::Execute failed. EnterpriseAdminProxy is nullptr.");
    }
}
} // namespace EDM
} // namespace OHOS