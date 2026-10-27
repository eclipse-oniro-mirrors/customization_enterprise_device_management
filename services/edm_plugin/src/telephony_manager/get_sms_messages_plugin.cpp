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

#include "get_sms_messages_plugin.h"

#include "edm_constants.h"
#include "edm_data_ability_utils.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "sms_message_info.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<GetSmsMessagesPlugin>());

constexpr int64_t MAX_SMS_MESSAGE_RETURN_SIZE = 128LL * 1024 * 1024;

static bool WriteSmsMessagesToReply(const std::vector<SmsMessageInfo> &messages, MessageParcel &reply)
{
    MessageParcel tempParcel;
    tempParcel.SetMaxCapacity(EdmConstants::MAX_PARCEL_CAPACITY_OF_ASHMEM);
    if (!tempParcel.WriteInt32(0)) {
        EDMLOGE("GetSmsMessagesPlugin: Write count placeholder failed.");
        return false;
    }
    int32_t actualCount = 0;
    for (const auto &msg : messages) {
        if (tempParcel.GetDataSize() > MAX_SMS_MESSAGE_RETURN_SIZE) {
            EDMLOGI("GetSmsMessagesPlugin: Data size exceeds limit, truncated at %{public}d records.", actualCount);
            break;
        }
        if (!msg.Marshalling(tempParcel)) {
            EDMLOGE("GetSmsMessagesPlugin: Marshalling failed at index %{public}d.", actualCount);
            break;
        }
        actualCount++;
    }
    uint8_t *dataPtr = reinterpret_cast<uint8_t *>(tempParcel.GetData());
    if (dataPtr != nullptr) {
        *(reinterpret_cast<int32_t *>(dataPtr)) = actualCount;
    }
    size_t dataSize = tempParcel.GetDataSize();
    if (!reply.WriteInt32(ERR_OK)) {
        EDMLOGE("GetSmsMessagesPlugin: Write ERR_OK failed.");
        return false;
    }
    if (!reply.WriteInt32(static_cast<int32_t>(dataSize))) {
        EDMLOGE("GetSmsMessagesPlugin: Write dataSize failed.");
        return false;
    }
    if (!reply.WriteRawData(reinterpret_cast<const void *>(tempParcel.GetData()), dataSize)) {
        EDMLOGE("GetSmsMessagesPlugin: WriteRawData failed, dataSize = %{public}zu.", dataSize);
        return false;
    }
    return true;
}

GetSmsMessagesPlugin::GetSmsMessagesPlugin()
{
    EDMLOGI("GetSmsMessagesPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::GET_SMS_MESSAGES;
    policyName_ = PolicyName::POLICY_GET_SMS_MESSAGES;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_READ_MESSAGES,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode GetSmsMessagesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("GetSmsMessagesPlugin OnGetPolicy.");
    int64_t startTime = data.ReadInt64();
    int64_t endTime = data.ReadInt64();
    std::string telephoneNumber = data.ReadString();

    if (startTime < 0 || endTime < 0 || startTime > endTime) {
        EDMLOGE("GetSmsMessagesPlugin invalid time range: startTime=%{public}lld endTime=%{public}lld",
            static_cast<long long>(startTime), static_cast<long long>(endTime));
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }

    std::vector<SmsMessageInfo> messages;
    ErrCode ret = QuerySmsMessages(startTime, endTime, telephoneNumber, messages);
    if (FAILED(ret)) {
        EDMLOGE("GetSmsMessagesPlugin QuerySmsMessages failed, ret=%{public}d", ret);
        reply.WriteInt32(ret);
        return ret;
    }
    EDMLOGI("GetSmsMessagesPlugin return size=%{public}zu", messages.size());

    if (!WriteSmsMessagesToReply(messages, reply)) {
        EDMLOGE("GetSmsMessagesPlugin WriteSmsMessagesToReply failed.");
        reply.WriteInt32(EdmReturnErrCode::EXECUTE_TIME_OUT);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    EDMLOGI("GetSmsMessagesPlugin OnGetPolicy success, count = %{public}zu.", messages.size());
    return ERR_OK;
}

ErrCode GetSmsMessagesPlugin::QuerySmsMessages(int64_t startTime, int64_t endTime,
    const std::string &telephoneNumber, std::vector<SmsMessageInfo> &messages)
{
    EDMLOGI("GetSmsMessagesPlugin QuerySmsMessages startTime=%{public}lld endTime=%{public}lld "
        "telephoneNumber=%{public}s",
        static_cast<long long>(startTime), static_cast<long long>(endTime), telephoneNumber.c_str());
    std::vector<SmsQueryResult> results;
    EDMLOGI("GetSmsMessagesPlugin::QuerySmsMessages GetSmsMessages start");
    ErrCode ret = EdmDataAbilityUtils::GetSmsMessages(startTime, endTime, telephoneNumber, results);
    if (FAILED(ret)) {
        EDMLOGE("GetSmsMessagesPlugin EdmDataAbilityUtils::GetSmsMessages failed, ret=%{public}d", ret);
        return ret;
    }
    for (const auto &result : results) {
        SmsMessageInfo info;
        info.slotId = result.slotId;
        info.telephoneNumber = result.telephoneNumber;
        info.content = result.content;
        info.timer = result.timer;
        info.isSender = result.isSender;
        messages.push_back(info);
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
