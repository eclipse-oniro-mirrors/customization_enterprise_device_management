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
 
#include "print_policy_util.h"
 
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "enterprise_device_mgr_proxy.h"
#include "func_code.h"
 
namespace OHOS {
namespace EDM {
 
namespace {
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";
}
 
ErrCode PrintPolicyUtil::GetPrintPolicy(int32_t userId, std::string &json)
{
    EDMLOGI("PrintPolicyUtil::GetPrintPolicy userId=%{public}d", userId);
    json = "{}";
 
    if (!EnterpriseDeviceMgrProxy::GetInstance()->IsEdmEnabled()) {
        EDMLOGI("PrintPolicyUtil::GetPrintPolicy edm not enabled");
        return ERR_OK;
    }
 
    std::vector<std::string> ipAddresses;
 
    // Step 1: Query device-level policy. If non-empty, device-level mode is active.
    if (!QueryDeviceLevelPolicy(ipAddresses)) {
        // Step 2: Fall back to user-level policy
        QueryUserLevelPolicy(userId, ipAddresses);
    }
 
    // Step 3: Build JSON result
    if (!ipAddresses.empty()) {
        json = BuildPrintPolicyJson(ipAddresses);
    }
 
    return ERR_OK;
}
 
bool PrintPolicyUtil::QueryDeviceLevelPolicy(std::vector<std::string> &ipAddresses)
{
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(WITHOUT_ADMIN);
 
    MessageParcel reply;
    if (EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(
        EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_DEVICE, data, reply)) {
        int32_t ret = ERR_INVALID_VALUE;
        if (reply.ReadInt32(ret) && ret == ERR_OK) {
            reply.ReadStringVector(&ipAddresses);
        }
    }
    return !ipAddresses.empty();
}
 
bool PrintPolicyUtil::QueryUserLevelPolicy(int32_t userId, std::vector<std::string> &ipAddresses)
{
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(WITHOUT_ADMIN);
 
    MessageParcel reply;
    if (EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(
        EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_ACCOUNT, data, reply)) {
        int32_t ret = ERR_INVALID_VALUE;
        if (reply.ReadInt32(ret) && ret == ERR_OK) {
            reply.ReadStringVector(&ipAddresses);
        }
    }
    return !ipAddresses.empty();
}
 
std::string PrintPolicyUtil::BuildPrintPolicyJson(const std::vector<std::string> &ipAddresses)
{
    std::string json = "{\"printer_policies\":[";
    for (size_t i = 0; i < ipAddresses.size(); ++i) {
        if (i > 0) {
            json += ",";
        }
        json += "{\"device_ip\":\"" + ipAddresses[i] + "\"}";
    }
    json += "]}";
    return json;
}
 
} // namespace EDM
} // namespace OHOS