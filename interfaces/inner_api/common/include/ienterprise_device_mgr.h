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

#ifndef INTERFACES_INNER_API_INCLUDE_IENTERPRISE_DEVICE_MGR_H
#define INTERFACES_INNER_API_INCLUDE_IENTERPRISE_DEVICE_MGR_H
#include <string>

#include "admin_type.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "element_name.h"
#include "ent_info.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"

namespace OHOS {
namespace EDM {
class IEnterpriseDeviceMgr : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.edm.IEnterpriseDeviceMgr");
    virtual ErrCode EnableAdmin(AppExecFwk::ElementName &admin, EntInfo &entInfo, AdminType type, int32_t userId) = 0;
    virtual ErrCode DisableAdmin(AppExecFwk::ElementName &admin, int32_t userId) = 0;
    virtual ErrCode DisableSuperAdmin(const std::string &bundleName) = 0;
    virtual ErrCode HandleDevicePolicy(uint32_t code, AppExecFwk::ElementName &admin, MessageParcel &data,
        MessageParcel &reply, int32_t userId) = 0;
    virtual ErrCode GetDevicePolicy(uint32_t code, MessageParcel &data, MessageParcel &reply, int32_t userId) = 0;
    virtual ErrCode GetEnabledAdmin(AdminType type, std::vector<std::string> &enabledAdminList) = 0;
    virtual ErrCode GetEnterpriseInfo(AppExecFwk::ElementName &admin, MessageParcel &reply) = 0;
    virtual ErrCode SetEnterpriseInfo(AppExecFwk::ElementName &admin, EntInfo &entInfo) = 0;
    virtual ErrCode SubscribeManagedEvent(const AppExecFwk::ElementName &admin,
        const std::vector<uint32_t> &events) = 0;
    virtual ErrCode UnsubscribeManagedEvent(const AppExecFwk::ElementName &admin,
        const std::vector<uint32_t> &events) = 0;
    virtual bool IsSuperAdmin(const std::string &bundleName) = 0;
    virtual bool IsAdminEnabled(AppExecFwk::ElementName &admin, int32_t userId) = 0;
    virtual ErrCode AuthorizeAdmin(const AppExecFwk::ElementName &admin, const std::string &bundleName) = 0;
    virtual ErrCode GetSuperAdmin(MessageParcel &reply) = 0;
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_INCLUDE_IENTERPRISE_DEVICE_MGR_H
