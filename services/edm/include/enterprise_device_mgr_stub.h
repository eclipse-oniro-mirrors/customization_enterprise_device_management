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

#ifndef SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_STUB_ABILITY_H
#define SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_STUB_ABILITY_H
#include <map>
#include "func_code_utils.h"
#include "edm_log.h"
#include "ienterprise_device_mgr.h"
#include "iremote_stub.h"

namespace OHOS {
namespace EDM {
class EnterpriseDeviceMgrStub : public IRemoteStub<IEnterpriseDeviceMgr> {
public:
    EnterpriseDeviceMgrStub();
    ~EnterpriseDeviceMgrStub();
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    using EnterpriseDeviceManagerFunc = int32_t (EnterpriseDeviceMgrStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, EnterpriseDeviceManagerFunc> memberFuncMap_;
    void AddCallFuncMap();
    ErrCode EnableAdminInner(MessageParcel &data, MessageParcel &reply);
    ErrCode DisableAdminInner(MessageParcel &data, MessageParcel &reply);
    ErrCode DisableSuperAdminInner(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleDevicePolicyInner(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode GetDevicePolicyInner(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode GetReqEdmPermissionsInner(MessageParcel &data, MessageParcel &reply);
    ErrCode GetEnabledAdminInner(MessageParcel &data, MessageParcel &reply);
    ErrCode GetEnterpriseInfoInner(MessageParcel &data, MessageParcel &reply);
    ErrCode SetEnterpriseInfoInner(MessageParcel &data, MessageParcel &reply);
    ErrCode IsSuperAdminInner(MessageParcel &data, MessageParcel &reply);
    ErrCode IsAdminEnabledInner(MessageParcel &data, MessageParcel &reply);
    ErrCode SubscribeManagedEventInner(MessageParcel &data, MessageParcel &reply);
    ErrCode UnsubscribeManagedEventInner(MessageParcel &data, MessageParcel &reply);
    ErrCode SubscribeManagedEventInner(MessageParcel &data, MessageParcel &reply, bool subscribe);
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_STUB_ABILITY_H
