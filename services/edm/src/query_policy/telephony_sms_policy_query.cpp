/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "telephony_sms_policy_query.h"

#include "ashmem.h"
#include "edm_constants.h"
#include "telephony_sms_policy_serializer.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
namespace {
bool WriteSmsNumberListToReply(const std::vector<std::string> &numberList, MessageParcel &reply)
{
    MessageParcel tempParcel;
    (void)tempParcel.SetMaxCapacity(EdmConstants::MAX_PARCEL_CAPACITY_OF_ASHMEM);
    if (!tempParcel.WriteStringVector(numberList)) {
        EDMLOGE("WriteSmsNumberListToReply: WriteStringVector failed.");
        return false;
    }
    size_t dataSize = tempParcel.GetDataSize();
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(EdmConstants::SmsPolicy::NUMBER_LIST_ASHMEM_NAME.c_str(), dataSize);
    if (ashmem == nullptr) {
        EDMLOGE("WriteSmsNumberListToReply: CreateAshmem failed.");
        return false;
    }
    if (!ashmem->MapReadAndWriteAshmem()) {
        EDMLOGE("WriteSmsNumberListToReply: MapReadAndWriteAshmem failed.");
        return false;
    }
    int32_t offset = 0;
    if (!ashmem->WriteToAshmem(reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize, offset)) {
        EDMLOGE("WriteSmsNumberListToReply: WriteToAshmem failed.");
        return false;
    }
    if (!reply.WriteInt32(static_cast<int32_t>(dataSize))) {
        EDMLOGE("WriteSmsNumberListToReply: Write dataSize failed.");
        return false;
    }
    if (!reply.WriteAshmem(ashmem)) {
        EDMLOGE("WriteSmsNumberListToReply: WriteAshmem failed.");
        return false;
    }
    return true;
}
} // namespace
std::string TelephonySmsPolicyQuery::GetPolicyName()
{
    return PolicyName::POLICY_TELEPHONY_SMS_POLICY;
}

std::string TelephonySmsPolicyQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY;
}

ErrCode TelephonySmsPolicyQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    const std::string smsType = data.ReadString();
    const int32_t flag = data.ReadInt32();
    EDMLOGI("TelephonySmsPolicyQuery::OnGetPolicy smsType:%{public}s, flag:%{public}d", smsType.c_str(), flag);

    auto serializer = TelephonySmsPolicySerializer::GetInstance();
    std::map<std::string, TelephonySmsPolicyType> policies;
    if (!serializer->Deserialize(policyData, policies)) {
        EDMLOGE("TelephonySmsPolicyQuery::OnGetPolicy Deserialize fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    std::vector<std::string> numberList;
    auto it = policies.find(smsType);
    if (it != policies.end() && flag == it->second.policyFlag) {
        numberList = it->second.numberList;
    }
    if (!WriteSmsNumberListToReply(numberList, reply)) {
        EDMLOGE("TelephonySmsPolicyQuery::OnGetPolicy WriteSmsNumberListToReply failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS