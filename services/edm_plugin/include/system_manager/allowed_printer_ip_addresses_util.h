/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
 
#ifndef EDM_SERVICES_EDM_PLUGIN_ALLOWED_PRINTER_IP_ADDRESSES_UTIL_H
#define EDM_SERVICES_EDM_PLUGIN_ALLOWED_PRINTER_IP_ADDRESSES_UTIL_H
 
#include <string>
#include <vector>
 
#include "array_string_serializer.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_publish_info.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "ipolicy_manager.h"
#include "message_parcel.h"
#include "message_option.h"
#include "want.h"
 
namespace OHOS {
namespace EDM {
 
enum class AllowedPrinterIpAddressesType : uint32_t {
    DEVICE_TYPE = 0,
    USER_TYPE = 1,
};
 
class AllowedPrinterIpAddressesUtil {
public:
    static ErrCode OnSetPolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
        std::vector<std::string> &mergeData, int32_t userId, AllowedPrinterIpAddressesType type, uint32_t maxSize,
        uint32_t maxReturnErrCode);
    
    static ErrCode OnRemovePolicy(std::vector<std::string> &data, std::vector<std::string> &currentData,
        std::vector<std::string> &mergeData, int32_t userId, AllowedPrinterIpAddressesType type, uint32_t maxSize,
        uint32_t maxReturnErrCode);
private:
    static bool IsDeviceLevelPolicySet();
    static bool IsAnyUserLevelPolicySet();
 
public:
    static ErrCode CheckPolicyConflict(AllowedPrinterIpAddressesType type);
    static void NotifyPrintPolicyChanged(int32_t userId, AllowedPrinterIpAddressesType type);
};
 
} // namespace EDM
} // namespace OHOS
#endif // EDM_SERVICES_EDM_PLUGIN_ALLOWED_PRINTER_IP_ADDRESSES_UTIL_H