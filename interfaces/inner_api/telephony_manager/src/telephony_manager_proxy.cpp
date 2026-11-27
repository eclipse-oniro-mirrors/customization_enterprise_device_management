/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "telephony_manager_proxy.h"

#include <cstdlib>
#include "ashmem.h"
#include "securec.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "func_code.h"
#include "message_parcel_utils.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<TelephonyManagerProxy> TelephonyManagerProxy::instance_ = nullptr;
std::once_flag TelephonyManagerProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

namespace {
bool WriteSmsNumberListToAshmem(const std::vector<std::string> &numbers, MessageParcel &data)
{
    MessageParcel tempParcel;
    (void)tempParcel.SetMaxCapacity(EdmConstants::MAX_PARCEL_CAPACITY_OF_ASHMEM);
    if (!tempParcel.WriteStringVector(numbers)) {
        EDMLOGE("WriteSmsNumberListToAshmem: WriteStringVector failed.");
        return false;
    }
    size_t dataSize = tempParcel.GetDataSize();
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(EdmConstants::SmsPolicy::NUMBER_LIST_ASHMEM_NAME.c_str(), dataSize);
    if (ashmem == nullptr) {
        EDMLOGE("WriteSmsNumberListToAshmem: CreateAshmem failed.");
        return false;
    }
    if (!ashmem->MapReadAndWriteAshmem()) {
        EDMLOGE("WriteSmsNumberListToAshmem: MapReadAndWriteAshmem failed.");
        return false;
    }
    int32_t offset = 0;
    if (!ashmem->WriteToAshmem(reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize, offset)) {
        EDMLOGE("WriteSmsNumberListToAshmem: WriteToAshmem failed.");
        return false;
    }
    if (!data.WriteInt32(static_cast<int32_t>(dataSize))) {
        EDMLOGE("WriteSmsNumberListToAshmem: WriteInt32 dataSize failed.");
        return false;
    }
    if (!data.WriteAshmem(ashmem)) {
        EDMLOGE("WriteSmsNumberListToAshmem: WriteAshmem failed.");
        return false;
    }
    return true;
}

ErrCode ReadSmsNumberListFromAshmem(MessageParcel &parcel, std::vector<std::string> &numbers)
{
    int32_t dataSize = parcel.ReadInt32();
    if (dataSize <= 0 || static_cast<size_t>(dataSize) > EdmConstants::MAX_PARCEL_CAPACITY_OF_ASHMEM) {
        EDMLOGE("ReadSmsNumberListFromAshmem: invalid dataSize %{public}d.", dataSize);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<Ashmem> ashmem = parcel.ReadAshmem();
    if (ashmem == nullptr) {
        EDMLOGE("ReadSmsNumberListFromAshmem: ReadAshmem failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (!ashmem->MapReadOnlyAshmem()) {
        EDMLOGE("ReadSmsNumberListFromAshmem: MapReadOnlyAshmem failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t offset = 0;
    const void *ashDataPtr = ashmem->ReadFromAshmem(dataSize, offset);
    if (ashDataPtr == nullptr) {
        EDMLOGE("ReadSmsNumberListFromAshmem: ReadFromAshmem failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    void *buffer = malloc(dataSize);
    if (buffer == nullptr) {
        EDMLOGE("ReadSmsNumberListFromAshmem: malloc buffer failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (memcpy_s(buffer, dataSize, ashDataPtr, dataSize) != EOK) {
        free(buffer);
        EDMLOGE("ReadSmsNumberListFromAshmem: memcpy_s failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel tempParcel;
    if (!tempParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        free(buffer);
        EDMLOGE("ReadSmsNumberListFromAshmem: ParseFrom failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (!tempParcel.ReadStringVector(&numbers)) {
        EDMLOGE("ReadSmsNumberListFromAshmem: ReadStringVector failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace

TelephonyManagerProxy::TelephonyManagerProxy() {}

TelephonyManagerProxy::~TelephonyManagerProxy() {}

std::shared_ptr<TelephonyManagerProxy> TelephonyManagerProxy::GetTelephonyManagerProxy()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<TelephonyManagerProxy>();
        }
    });
    return instance_;
}

int32_t TelephonyManagerProxy::SetSimDisabled(MessageParcel &data)
{
    EDMLOGD("TelephonyManagerProxy::SetSimDisabled.");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_SIM);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::SetSimEnabled(MessageParcel &data)
{
    EDMLOGD("TelephonyManagerProxy::SetSimEnabled.");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DISALLOWED_SIM);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::IsSimDisabled(MessageParcel &data, bool &result)
{
    EDMLOGD("TelephonyManagerProxy::IsSimDisabled");
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::DISALLOWED_SIM, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool isSuccess = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!isSuccess) {
        EDMLOGE("IsSimDisabled:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(result);
    return ERR_OK;
}

int32_t TelephonyManagerProxy::AddCallPolicyNumbers(const AppExecFwk::ElementName &admin,
    const std::string &callType, const int32_t policyFlag, const std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::AddCallPolicyNumbers.");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(callType);
    data.WriteInt32(policyFlag);
    if (numbers.size() > EdmConstants::CallPolicy::NUMBER_LIST_MAX_SIZE) {
        return ERR_INVALID_VALUE;
    }
    data.WriteStringVector(numbers);
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::TELEPHONY_CALL_POLICY);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::RemoveCallPolicyNumbers(const AppExecFwk::ElementName &admin,
    const std::string &callType, const int32_t policyFlag, const std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::RemoveCallPolicyNumbers.");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(callType);
    data.WriteInt32(policyFlag);
    if (numbers.size() > EdmConstants::CallPolicy::NUMBER_LIST_MAX_SIZE) {
        return ERR_INVALID_VALUE;
    }
    data.WriteStringVector(numbers);
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::TELEPHONY_CALL_POLICY);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::GetCallPolicyNumbers(MessageParcel &data, std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::GetCallPolicyNumbers with MessageParcel.");
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::TELEPHONY_CALL_POLICY, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetCallPolicyNumbers fail. %{public}d", ret);
        return ret;
    }
    reply.ReadStringVector(&numbers);
    EDMLOGD("EnterpriseDeviceMgrProxy:GetCallPolicyNumbers success");
    return ERR_OK;
}

int32_t TelephonyManagerProxy::AddSmsPolicyNumbers(const std::string &smsType,
    const int32_t policyFlag, const std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::AddSmsPolicyNumbers.");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(EdmConstants::DEFAULT_USER_ID);
    data.WriteString(smsType);
    data.WriteInt32(policyFlag);
    if (!WriteSmsNumberListToAshmem(numbers, data)) {
        EDMLOGE("TelephonyManagerProxy::AddSmsPolicyNumbers WriteSmsNumberListToAshmem failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE_NEW((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::TELEPHONY_SMS_POLICY);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicyNew(funcCode, data);
}

int32_t TelephonyManagerProxy::RemoveSmsPolicyNumbers(const std::string &smsType,
    const int32_t policyFlag, const std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::RemoveSmsPolicyNumbers.");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(EdmConstants::DEFAULT_USER_ID);
    data.WriteString(smsType);
    data.WriteInt32(policyFlag);
    if (!WriteSmsNumberListToAshmem(numbers, data)) {
        EDMLOGE("TelephonyManagerProxy::RemoveSmsPolicyNumbers WriteSmsNumberListToAshmem failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE_NEW((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::TELEPHONY_SMS_POLICY);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicyNew(funcCode, data);
}

int32_t TelephonyManagerProxy::GetSmsPolicyNumbers(MessageParcel &data, std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::GetSmsPolicyNumbers with MessageParcel.");
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicyNew(EdmInterfaceCode::TELEPHONY_SMS_POLICY, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetSmsPolicyNumbers fail. %{public}d", ret);
        return ret;
    }
    ret = ReadSmsNumberListFromAshmem(reply, numbers);
    if (ret != ERR_OK) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetSmsPolicyNumbers ReadSmsNumberListFromAshmem fail. %{public}d", ret);
        return ret;
    }
    EDMLOGD("EnterpriseDeviceMgrProxy:GetSmsPolicyNumbers success");
    return ERR_OK;
}

bool TelephonyManagerProxy::IsAllowedTelephonySms(const std::string &smsType, const std::string &number)
{
    EDMLOGI("TelephonyManagerProxy::IsAllowedTelephonySms");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return true;
    }
    if (!proxy->IsEdmEnabled()) {
        EDMLOGI("The device is not under control.");
        return true;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(EdmConstants::DEFAULT_USER_ID);
    data.WriteInt32(static_cast<int32_t>(QueryPolicy::ALL));
    data.WriteString(smsType);
    data.WriteString(number);
    int32_t ret = proxy->GetPolicyNew(EdmInterfaceCode::IS_ALLOWED_TELEPHONY_SMS, data, reply);
    if (ret != ERR_OK) {
        EDMLOGW("TelephonyManagerProxy:IsAllowedTelephonySms GetPolicyNew fail. %{public}d", ret);
        return true;
    }
    bool isAllowed = true;
    reply.ReadBool(isAllowed);
    EDMLOGI("TelephonyManagerProxy:IsAllowedTelephonySms result=%{public}d", isAllowed);
    return isAllowed;
}

bool TelephonyManagerProxy::IsAllowedTelephonyCall(const std::string &callType, const std::string &number)
{
    EDMLOGI("TelephonyManagerProxy::IsAllowedTelephonyCall");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return true;
    }
    if (!proxy->IsEdmEnabled()) {
        EDMLOGI("The device is not under control.");
        return true;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(EdmConstants::DEFAULT_USER_ID);
    data.WriteInt32(static_cast<int32_t>(QueryPolicy::ALL));
    data.WriteString(callType);
    data.WriteString(number);
    int32_t ret = proxy->GetPolicyNew(EdmInterfaceCode::IS_ALLOWED_TELEPHONY_CALL, data, reply);
    if (ret != ERR_OK) {
        EDMLOGW("TelephonyManagerProxy:IsAllowedTelephonyCall GetPolicyNew fail. %{public}d", ret);
        return true;
    }
    bool isAllowed = true;
    reply.ReadBool(isAllowed);
    EDMLOGI("TelephonyManagerProxy:IsAllowedTelephonyCall result=%{public}d", isAllowed);
    return isAllowed;
}

int32_t TelephonyManagerProxy::HangupCalling(MessageParcel &data)
{
    EDMLOGD("TelephonyManagerProxy::HangupCalling.");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::HANG_UP_CALLING);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::ActiveSim(MessageParcel &data)
{
    EDMLOGD("TelephonyManagerProxy::ActiveSim ");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_SIM);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::DeactiveSim(MessageParcel &data)
{
    EDMLOGD("TelephonyManagerProxy::DeactiveSim");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_SIM);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::SetDefaultDataSim(MessageParcel &data)
{
    EDMLOGD("TelephonyManagerProxy::SetDefaultDataSim");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_DEFAULT_DATA_SIM);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::GetDefaultDataSim(MessageParcel &data, int32_t &simId)
{
    EDMLOGD("TelephonyManagerProxy::GetDefaultDataSim");
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::SET_DEFAULT_DATA_SIM, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool isSuccess = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!isSuccess) {
        EDMLOGE("GetDefaultDataSim:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadInt32(simId);
    return ERR_OK;
}

static ErrCode AllocAndCopyBuffer(void *&buffer, int32_t size, const void *src)
{
    if (size <= 0) {
        EDMLOGE("GetCallLogs: invalid size %{public}d.", size);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    buffer = malloc(size);
    if (buffer == nullptr) {
        EDMLOGE("GetCallLogs: malloc failed.");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    if (memcpy_s(buffer, size, src, size) != EOK) {
        free(buffer);
        buffer = nullptr;
        EDMLOGE("GetCallLogs: memcpy_s failed.");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}

static ErrCode ReadBufferFromReply(MessageParcel &reply, int32_t dataSize, void *&buffer)
{
    const void *src = reply.ReadRawData(dataSize);
    if (src == nullptr) {
        EDMLOGE("GetCallLogs: read source data failed.");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return AllocAndCopyBuffer(buffer, dataSize, src);
}

static ErrCode ParseCallLogsFromBuffer(void *buffer, int32_t dataSize, std::vector<CallLogInfo> &callLogs)
{
    MessageParcel tempParcel;
    if (!tempParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        EDMLOGE("GetCallLogs: ParseFrom failed.");
        free(buffer);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    int32_t count = tempParcel.ReadInt32();
    size_t readableDataSize = tempParcel.GetReadableBytes();
    if (count < 0 || static_cast<size_t>(count) > readableDataSize ||
        callLogs.max_size() < static_cast<size_t>(count)) {
        EDMLOGE("GetCallLogs: count check failed, count=%{public}d, readable=%{public}zu",
            count, readableDataSize);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    callLogs.reserve(static_cast<size_t>(count));
    for (int32_t i = 0; i < count; ++i) {
        CallLogInfo log;
        log.createTime = tempParcel.ReadInt64();
        log.startTime = tempParcel.ReadInt64();
        log.endTime = tempParcel.ReadInt64();
        log.isIncoming = tempParcel.ReadBool();
        log.slotId = tempParcel.ReadInt32();
        log.telephoneNumber = tempParcel.ReadString();
        callLogs.push_back(log);
    }
    EDMLOGD("GetCallLogs success, count = %{public}d", count);
    return ERR_OK;
}

int32_t TelephonyManagerProxy::GetCallLogs(const TelephonyQueryConfig &config,
    std::vector<CallLogInfo> &callLogs)
{
    EDMLOGD("TelephonyManagerProxy::GetCallLogs");
#ifdef FEATURE_PC_ONLY
    EDMLOGW("TelephonyManagerProxy::GetCallLogs not supported on pc");
    return ERR_OK;
#endif
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(EdmConstants::DEFAULT_USER_ID);
    data.WriteInt32(static_cast<int32_t>(QueryPolicy::SELF));
    data.WriteInt64(config.startTime);
    data.WriteInt64(config.endTime);
    data.WriteBool(config.hasTelephoneNumber);
    if (config.hasTelephoneNumber) {
        data.WriteString(config.telephoneNumber);
    }
    MessageParcel reply;
    int32_t ret = EnterpriseDeviceMgrProxy::GetInstance()->GetPolicyNew(
        EdmInterfaceCode::GET_CALL_LOGS, data, reply);
    if (ret != ERR_OK) {
        EDMLOGE("GetCallLogs:GetPolicyNew fail. %{public}d", ret);
        return ret;
    }
    int32_t dataSize = reply.ReadInt32();
    if (dataSize == 0) {
        EDMLOGI("GetCallLogs: empty result, dataSize = 0.");
        return ERR_OK;
    }
    if (dataSize < 0 || dataSize > static_cast<int32_t>(EdmConstants::MAX_PARCEL_CAPACITY_OF_ASHMEM)) {
        EDMLOGE("GetCallLogs: invalid dataSize %{public}d.", dataSize);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    void *buffer = nullptr;
    ErrCode errCode = ReadBufferFromReply(reply, dataSize, buffer);
    if (errCode != ERR_OK) {
        EDMLOGE("GetCallLogs: ReadBufferFromReply failed, ret = %{public}d.", errCode);
        return errCode;
    }
    errCode = ParseCallLogsFromBuffer(buffer, dataSize, callLogs);
    if (errCode != ERR_OK) {
        EDMLOGE("GetCallLogs: ParseCallLogsFromBuffer failed, ret = %{public}d.", errCode);
        return errCode;
    }
    EDMLOGI("GetCallLogs success, count = %{public}zu.", callLogs.size());
    return errCode;
}

static ErrCode ParseSmsMessagesFromBuffer(void *buffer, int32_t dataSize, std::vector<SmsMessageInfo> &messages)
{
    MessageParcel tempParcel;
    if (!tempParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        EDMLOGE("GetSmsMessages: ParseFrom failed.");
        free(buffer);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    int32_t count = tempParcel.ReadInt32();
    size_t readableDataSize = tempParcel.GetReadableBytes();
    if (count < 0 || static_cast<size_t>(count) > readableDataSize ||
        messages.max_size() < static_cast<size_t>(count)) {
        EDMLOGE("GetSmsMessages: count check failed, count=%{public}d, readable=%{public}zu",
            count, readableDataSize);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    for (int32_t i = 0; i < count; ++i) {
        std::unique_ptr<SmsMessageInfo> info(SmsMessageInfo::Unmarshalling(tempParcel));
        if (info == nullptr) {
            EDMLOGE("GetSmsMessages: Unmarshalling fail at index=%{public}d", i);
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
        }
        messages.push_back(*info);
    }
    EDMLOGD("GetSmsMessages success, count = %{public}d", count);
    return ERR_OK;
}

int32_t TelephonyManagerProxy::GetSmsMessages(const TelephonyQueryConfig &config,
    std::vector<SmsMessageInfo> &messages)
{
    EDMLOGD("TelephonyManagerProxy::GetSmsMessages");
#ifdef FEATURE_PC_ONLY
    EDMLOGW("TelephonyManagerProxy::GetSmsMessages not supported on pc");
    return ERR_OK;
#endif
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(EdmConstants::DEFAULT_USER_ID);
    data.WriteInt32(static_cast<int32_t>(QueryPolicy::SELF));
    data.WriteInt64(config.startTime);
    data.WriteInt64(config.endTime);
    data.WriteString(config.telephoneNumber);
    MessageParcel reply;
    auto ret = EnterpriseDeviceMgrProxy::GetInstance()->GetPolicyNew(EdmInterfaceCode::GET_SMS_MESSAGES, data, reply);
    if (ret != ERR_OK) {
        EDMLOGE("GetSmsMessages:GetPolicyNew fail. %{public}d", ret);
        return ret;
    }
    int32_t dataSize = reply.ReadInt32();
    if (dataSize == 0) {
        EDMLOGI("GetSmsMessages: empty result, dataSize = 0.");
        return ERR_OK;
    }
    if (dataSize < 0 || dataSize > static_cast<int32_t>(EdmConstants::MAX_PARCEL_CAPACITY_OF_ASHMEM)) {
        EDMLOGE("GetSmsMessages: invalid dataSize %{public}d.", dataSize);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    void *buffer = nullptr;
    ErrCode errCode = ReadBufferFromReply(reply, dataSize, buffer);
    if (errCode != ERR_OK) {
        EDMLOGE("GetSmsMessages: ReadBufferFromReply failed, ret = %{public}d.", errCode);
        return errCode;
    }
    errCode = ParseSmsMessagesFromBuffer(buffer, dataSize, messages);
    if (errCode != ERR_OK) {
        EDMLOGE("GetSmsMessages: ParseSmsMessagesFromBuffer failed, ret = %{public}d.", errCode);
        return errCode;
    }
    EDMLOGI("GetSmsMessages success, count = %{public}zu.", messages.size());
    return errCode;
}
} // namespace EDM
} // namespace OHOS
