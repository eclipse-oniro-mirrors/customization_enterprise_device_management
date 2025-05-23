/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_STUB_ABILITY_H
#define SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_STUB_ABILITY_H

#include <map>

#include "edm_log.h"
#include "external_manager_factory.h"
#include "func_code.h"
#include "ienterprise_device_mgr.h"
#include "iexternal_manager_factory.h"
#include "iremote_stub.h"
#include "permission_checker.h"
#include "enterprise_device_mgr_idl_stub.h"

namespace OHOS {
namespace EDM {
class EnterpriseDeviceMgrStub : public EnterpriseDeviceMgrIdlStub, public IEnterpriseDeviceMgr {
public:
    EnterpriseDeviceMgrStub();
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

protected:
    virtual std::shared_ptr<IExternalManagerFactory> GetExternalManagerFactory();

private:
    std::vector<uint32_t> systemCodeList;
    void InitSystemCodeList();
    ErrCode HandleDevicePolicyInner(uint32_t code, MessageParcel &data, MessageParcel &reply, int32_t userId);
    ErrCode GetDevicePolicyInner(uint32_t code, MessageParcel &data, MessageParcel &reply, int32_t userId);
    ErrCode CheckAndGetAdminProvisionInfoInner(uint32_t code, MessageParcel &data, MessageParcel &reply, int32_t
        userId);
    #ifdef EDM_SUPPORT_ALL_ENABLE
    ErrCode OnRemoteRequestIdl(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    #endif
    std::shared_ptr<IExternalManagerFactory> externalManagerFactory_ = std::make_shared<ExternalManagerFactory>();
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_STUB_ABILITY_H
