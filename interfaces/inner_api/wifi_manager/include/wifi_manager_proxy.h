/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_WIFI_MANAGER_INCLUDE_WIFI_MANAGER_PROXY_H
#define INTERFACES_INNER_API_WIFI_MANAGER_INCLUDE_WIFI_MANAGER_PROXY_H

#include "enterprise_device_mgr_proxy.h"
#ifdef WIFI_EDM_ENABLE
#include "edm_constants.h"
#include "func_code.h"
#include "wifi_id.h"
#include "wifi_msg.h"
#include "wifi_password.h"
#endif

namespace OHOS {
namespace EDM {
class WifiManagerProxy {
public:
    WifiManagerProxy();
    ~WifiManagerProxy();
    static std::shared_ptr<WifiManagerProxy> GetWifiManagerProxy();
    int32_t IsWifiActive(MessageParcel &data, bool &result);
#ifdef WIFI_EDM_ENABLE
    int32_t SetWifiProfile(MessageParcel &data);
    int32_t GetWifiList(MessageParcel &data, std::vector<WifiId> &result, EdmInterfaceCode policyCode);
    int32_t AddOrRemoveWifiList(MessageParcel &data, FuncOperateType operateType, EdmInterfaceCode code);
#endif
    int32_t SetWifiDisabled(MessageParcel &data);
    int32_t IsWifiDisabled(MessageParcel &data, bool &result);
    int32_t TurnOnWifi(MessageParcel &data);
    int32_t TurnOffWifi(MessageParcel &data);
private:
    static std::shared_ptr<WifiManagerProxy> instance_;
    static std::once_flag flag_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_WIFI_MANAGER_INCLUDE_WIFI_MANAGER_PROXY_H
