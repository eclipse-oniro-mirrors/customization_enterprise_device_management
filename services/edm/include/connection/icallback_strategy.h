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

#ifndef SERVICES_EDM_INCLUDE_CONNECTION_ICALLBACK_STRATEGY_H
#define SERVICES_EDM_INCLUDE_CONNECTION_ICALLBACK_STRATEGY_H

#include "enterprise_admin_proxy.h"

namespace OHOS {
namespace EDM {
class ICallbackStrategy {
public:
    virtual ~ICallbackStrategy() = default;

    virtual void Execute(const sptr<EnterpriseAdminProxy>& proxy);

    uint32_t GetCode() const { return code_; }

protected:
    ICallbackStrategy() = default;
    explicit ICallbackStrategy(uint32_t code) : code_(code) {}
    virtual void ExecuteImpl(const sptr<EnterpriseAdminProxy>& proxy) = 0;
    uint32_t code_ = 0;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_CONNECTION_ICALLBACK_STRATEGY_H