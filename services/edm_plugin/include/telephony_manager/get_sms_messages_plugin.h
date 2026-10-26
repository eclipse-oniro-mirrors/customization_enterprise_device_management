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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_TELEPHONY_MANAGER_GET_SMS_MESSAGES_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_TELEPHONY_MANAGER_GET_SMS_MESSAGES_PLUGIN_H

#include "iplugin.h"
#include "sms_message_info.h"

namespace OHOS {
namespace EDM {
class GetSmsMessagesPlugin : public IPlugin {
public:
    GetSmsMessagesPlugin();

    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
        int32_t userId) override;

private:
    ErrCode QuerySmsMessages(int64_t startTime, int64_t endTime, const std::string &telephoneNumber,
        std::vector<SmsMessageInfo> &messages);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_TELEPHONY_MANAGER_GET_SMS_MESSAGES_PLUGIN_H
