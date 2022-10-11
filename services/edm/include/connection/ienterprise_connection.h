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

#ifndef SERVICES_EDM_INCLUDE_CONNECTION_IENTERPRISE_CONNECTION_H
#define SERVICES_EDM_INCLUDE_CONNECTION_IENTERPRISE_CONNECTION_H

#include "ability_connect_callback_stub.h"
#include "enterprise_admin_proxy.h"

namespace OHOS {
namespace EDM {
class IEnterpriseConnection : public AAFwk::AbilityConnectionStub {
public:
    IEnterpriseConnection(const AAFwk::Want &want, uint32_t code,
        uint32_t userId) : want_(want), code_(code), userId_(userId) {};
    
    virtual ~IEnterpriseConnection() {};

    AAFwk::Want GetWant() const
    {
        return want_;
    }

    uint32_t GetUserId() const
    {
        return userId_;
    }
protected:
    AAFwk::Want want_;
    uint32_t code_;
    uint32_t userId_;

    sptr<EnterpriseAdminProxy> proxy_{nullptr};
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_CONNECTION_IENTERPRISE_CONNECTION_H