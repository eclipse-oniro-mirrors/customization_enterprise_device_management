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

#include "edm_log.h"
#include "func_code.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<DeviceInfoProxy> DeviceInfoProxy::instance_ = nullptr;
std::mutex DeviceInfoProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

DeviceInfoProxy::DeviceInfoProxy() {}

DeviceInfoProxy::~DeviceInfoProxy() {}

std::shared_ptr<DeviceInfoProxy> DeviceInfoProxy::GetDeviceInfoProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<DeviceInfoProxy> temp = std::make_shared<DeviceInfoProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t DeviceInfoProxy::GetDeviceSerial(AppExecFwk::ElementName &admin, std::string &info)
{
    return GetDeviceInfo(admin, info, EdmInterfaceCode::GET_DEVICE_SERIAL);
}

int32_t DeviceInfoProxy::GetDisplayVersion(AppExecFwk::ElementName &admin, std::string &info)
{
    return GetDeviceInfo(admin, info, EdmInterfaceCode::GET_DISPLAY_VERSION);
}

int32_t DeviceInfoProxy::GetDeviceName(AppExecFwk::ElementName &admin, std::string &info)
{
    return GetDeviceInfo(admin, info, EdmInterfaceCode::GET_DEVICE_NAME);
}

int32_t DeviceInfoProxy::GetDeviceInfo(AppExecFwk::ElementName &admin, std::string &info, int policyCode)
{
    EDMLOGD("DeviceInfoProxy::GetDeviceInfo %{public}d", policyCode);
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    proxy->GetPolicy(policyCode, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadString(info);
    return ERR_OK;
}

int32_t DeviceInfoProxy::GetDeviceInfoSync(AppExecFwk::ElementName &admin, const std::string &label, std::string &info)
{
    EDMLOGI("DeviceInfoProxy::GetDeviceInfoSync %{public}s", label.c_str());
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    data.WriteString(label);
    proxy->GetPolicy(EdmInterfaceCode::GET_DEVICE_INFO, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetDeviceInfoSync fail. %{public}d", ret);
        return ret;
    }
    reply.ReadString(info);
    return ERR_OK;
}
}  // namespace EDM
}  // namespace OHOS
