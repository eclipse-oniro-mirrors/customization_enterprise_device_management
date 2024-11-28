/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "datetime_manager_proxy.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "func_code.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<DatetimeManagerProxy> DatetimeManagerProxy::instance_ = nullptr;
std::once_flag DatetimeManagerProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

DatetimeManagerProxy::DatetimeManagerProxy() {}

DatetimeManagerProxy::~DatetimeManagerProxy() {}

std::shared_ptr<DatetimeManagerProxy> DatetimeManagerProxy::GetDatetimeManagerProxy()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<DatetimeManagerProxy>();
        }
    });
    return instance_;
}

int32_t DatetimeManagerProxy::SetDateTime(AppExecFwk::ElementName &admin, int64_t time,
    const std::string &permissionTag)
{
    EDMLOGD("DatetimeManagerProxy::SetDateTime");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(permissionTag);
    data.WriteInt64(time);
    return this->SetDateTime(data);
}

int32_t DatetimeManagerProxy::SetDateTime(MessageParcel &data)
{
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_DATETIME);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t DatetimeManagerProxy::DisallowModifyDateTime(AppExecFwk::ElementName &admin, bool disallow)
{
    EDMLOGD("DatetimeManagerProxy::DisallowModifyDateTime");
    return EnterpriseDeviceMgrProxy::GetInstance()->SetPolicyDisabled(admin, disallow,
        EdmInterfaceCode::DISALLOW_MODIFY_DATETIME, EdmConstants::PERMISSION_TAG_VERSION_11);
}

int32_t DatetimeManagerProxy::DisallowModifyDateTime(MessageParcel &data)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->SetPolicyDisabled(data,
        EdmInterfaceCode::DISALLOW_MODIFY_DATETIME);
}

int32_t DatetimeManagerProxy::IsModifyDateTimeDisallowed(AppExecFwk::ElementName *admin, bool &result)
{
    EDMLOGD("DatetimeManagerProxy::IsModifyDateTimeDisallowed");
    return EnterpriseDeviceMgrProxy::GetInstance()->IsPolicyDisabled(admin, EdmInterfaceCode::DISALLOW_MODIFY_DATETIME,
        result, EdmConstants::PERMISSION_TAG_VERSION_11);
}

int32_t DatetimeManagerProxy::IsModifyDateTimeDisallowed(MessageParcel &data, bool &result)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->IsPolicyDisabled(data, EdmInterfaceCode::DISALLOW_MODIFY_DATETIME,
        result);
}
} // namespace EDM
} // namespace OHOS
