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

#include "enterprise_admin_proxy.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
void EnterpriseAdminProxy::OnAdminEnabled()
{
    EDMLOGI("EnterpriseAdminProxy proxy OnAdminEnabled");
    SendRequest(COMMAND_ON_ADMIN_ENABLED);
}

void EnterpriseAdminProxy::OnAdminDisabled()
{
    EDMLOGI("EnterpriseAdminProxy proxy OnAdminDisabled");
    SendRequest(COMMAND_ON_ADMIN_DISABLED);
}

void EnterpriseAdminProxy::SendRequest(uint32_t code)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        EDMLOGE("EnterpriseAdminProxy::%{public}s write descriptor failed!", __func__);
        return;
    }
    Remote()->SendRequest(code, data, reply, option);
}
} // namespace EDM
} // namespace OHOS
