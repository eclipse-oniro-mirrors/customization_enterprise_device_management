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

#include "device_info_proxy.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "func_code.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<DeviceInfoProxy> DeviceInfoProxy::instance_ = nullptr;
std::once_flag DeviceInfoProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

DeviceInfoProxy::DeviceInfoProxy() {}

DeviceInfoProxy::~DeviceInfoProxy() {}

std::shared_ptr<DeviceInfoProxy> DeviceInfoProxy::GetDeviceInfoProxy()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<DeviceInfoProxy>();
        }
    });
    return instance_;
}

int32_t DeviceInfoProxy::GetDeviceSerial(MessageParcel &data, std::string &info)
{
    return GetDeviceInfo(data, EdmConstants::DeviceInfo::DEVICE_SERIAL, EdmInterfaceCode::GET_DEVICE_INFO, info);
}

int32_t DeviceInfoProxy::GetDisplayVersion(MessageParcel &data, std::string &info)
{
    return GetDeviceInfo(data, "", EdmInterfaceCode::GET_DISPLAY_VERSION, info);
}

int32_t DeviceInfoProxy::GetDeviceName(MessageParcel &data, std::string &info)
{
    return GetDeviceInfo(data, EdmConstants::DeviceInfo::DEVICE_NAME, EdmInterfaceCode::GET_DEVICE_INFO, info);
}

int32_t DeviceInfoProxy::GetDeviceInfo(MessageParcel &data, const std::string &label, int policyCode, std::string &info)
{
    EDMLOGD("DeviceInfoProxy::GetDeviceInfo %{public}d", policyCode);
    MessageParcel reply;
    // The synchronous interface requires the label
    if (!label.empty()) {
        data.WriteString(label);
    }
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(policyCode, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadString(info);
    return ERR_OK;
}
}  // namespace EDM
}  // namespace OHOS
