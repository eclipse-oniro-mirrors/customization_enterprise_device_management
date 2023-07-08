/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "usb_manager_proxy.h"

#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code.h"
#include "message_parcel_utils.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<UsbManagerProxy> UsbManagerProxy::instance_ = nullptr;
std::mutex UsbManagerProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

std::shared_ptr<UsbManagerProxy> UsbManagerProxy::GetUsbManagerProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<UsbManagerProxy> temp = std::make_shared<UsbManagerProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t UsbManagerProxy::SetUsbReadOnly(const AppExecFwk::ElementName &admin, bool readOnly)
{
    EDMLOGD("UsbManagerProxy::SetUsbReadOnly");
    return EnterpriseDeviceMgrProxy::GetInstance()->SetPolicyDisabled(admin, readOnly, EdmInterfaceCode::USB_READ_ONLY);
}
} // namespace EDM
} // namespace OHOS
