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

#include "get_call_logs_plugin.h"

#include <mutex>

#include "ashmem.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code.h"
#include "iplugin_manager.h"
#include "int_serializer.h"
#ifdef TELEPHONY_EDM_ENABLE
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "uri.h"
#endif

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(GetCallLogsPlugin::GetPlugin());

void GetCallLogsPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<GetCallLogsPlugin, int32_t>> ptr)
{
    EDMLOGI("GetCallLogsPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::GET_CALL_LOGS, PolicyName::POLICY_GET_CALL_LOGS,
        EdmPermission::PERMISSION_ENTERPRISE_READ_CALL_LOG, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(IntSerializer::GetInstance());
}

#ifdef TELEPHONY_EDM_ENABLE
constexpr const char *CALL_LOG_URI = "datashare:///com.ohos.calllogability/calls/calllog";
constexpr const char *CALL_LOG_COLUMN_ID = "id";
constexpr const char *CALL_LOG_COLUMN_PHONE_NUMBER = "phone_number";
constexpr const char *CALL_LOG_COLUMN_BEGIN_TIME = "begin_time";
constexpr const char *CALL_LOG_COLUMN_END_TIME = "end_time";
constexpr const char *CALL_LOG_COLUMN_CALL_DIRECTION = "call_direction";
constexpr const char *CALL_LOG_COLUMN_SLOT_ID = "slot_id";
constexpr int32_t COLUMN_INDEX_PHONE_NUMBER = 1;
constexpr int32_t COLUMN_INDEX_BEGIN_TIME = 2;
constexpr int32_t COLUMN_INDEX_END_TIME = 3;
constexpr int32_t COLUMN_INDEX_CALL_DIRECTION = 4;
constexpr int32_t COLUMN_INDEX_SLOT_ID = 5;
constexpr int32_t CALL_DIRECTION_IN = 0;
constexpr int32_t ROW_FETCH_SUCCESS = 0;
constexpr size_t ESTIMATED_RECORD_SIZE = 64;
constexpr int64_t ONE_DAY_MILLIS = 24LL * 60 * 60 * 1000;
constexpr int64_t MAX_TIME_RANGE_MILLIS = 31LL * ONE_DAY_MILLIS;
constexpr const char *CALL_LOG_ASHMEM_NAME = "edm_call_logs_";
constexpr int32_t DATASHARE_WAIT_TIME = 10;
static int32_t ashmemNum_ = 0;
static std::mutex ashmemMutex_;
static std::shared_ptr<DataShare::DataShareHelper> CreateCallLogHelper()
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        EDMLOGE("GetCallLogsPlugin: GetSystemAbilityManager failed.");
        return nullptr;
    }
    auto remote = saManager->GetSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    if (remote == nullptr) {
        EDMLOGE("GetCallLogsPlugin: GetSystemAbility ENTERPRISE_DEVICE_MANAGER_SA_ID failed.");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remote, std::string(CALL_LOG_URI), "", DATASHARE_WAIT_TIME);
}

static DataShare::DataSharePredicates BuildPredicates(const TelephonyQueryConfig &config)
{
    DataShare::DataSharePredicates predicates;
    predicates.GreaterThanOrEqualTo(CALL_LOG_COLUMN_BEGIN_TIME, std::to_string(config.startTime));
    predicates.And()->LessThanOrEqualTo(CALL_LOG_COLUMN_BEGIN_TIME, std::to_string(config.endTime));
    if (config.hasTelephoneNumber && !config.telephoneNumber.empty()) {
        predicates.And()->EqualTo(CALL_LOG_COLUMN_PHONE_NUMBER, config.telephoneNumber);
    }
    predicates.OrderByDesc(CALL_LOG_COLUMN_BEGIN_TIME);
    return predicates;
}

static std::vector<std::string> BuildResultColumns()
{
    return {
        CALL_LOG_COLUMN_ID,
        CALL_LOG_COLUMN_PHONE_NUMBER,
        CALL_LOG_COLUMN_BEGIN_TIME,
        CALL_LOG_COLUMN_END_TIME,
        CALL_LOG_COLUMN_CALL_DIRECTION,
        CALL_LOG_COLUMN_SLOT_ID,
    };
}

static ErrCode QueryCallLogs(const TelephonyQueryConfig &config, std::vector<CallLogInfo> &callLogs)
{
    auto helper = CreateCallLogHelper();
    if (helper == nullptr) {
        EDMLOGE("GetCallLogsPlugin: CreateCallLogHelper failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto predicates = BuildPredicates(config);
    auto columns = BuildResultColumns();
    Uri uri(CALL_LOG_URI);
    auto resultSet = helper->Query(uri, predicates, columns);
    if (resultSet == nullptr) {
        EDMLOGE("GetCallLogsPlugin: Query call log failed.");
        helper->Release();
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    while (resultSet->GoToNextRow() == ROW_FETCH_SUCCESS) {
        if (callLogs.size() * ESTIMATED_RECORD_SIZE >= EdmConstants::MAX_PARCEL_CAPACITY) {
            EDMLOGI("GetCallLogsPlugin: Estimated data size exceeds limit, stop at %{public}zu records.",
                callLogs.size());
            break;
        }
        CallLogInfo log;
        int64_t beginTime = 0;
        resultSet->GetLong(COLUMN_INDEX_BEGIN_TIME, beginTime);
        log.startTime = beginTime;
        int64_t endTime = 0;
        resultSet->GetLong(COLUMN_INDEX_END_TIME, endTime);
        log.endTime = endTime;
        int32_t callDirection = 1;
        resultSet->GetInt(COLUMN_INDEX_CALL_DIRECTION, callDirection);
        log.isIncoming = (callDirection == CALL_DIRECTION_IN);
        int32_t slotId = -1;
        resultSet->GetInt(COLUMN_INDEX_SLOT_ID, slotId);
        log.slotId = slotId;
        std::string phoneNumber;
        resultSet->GetString(COLUMN_INDEX_PHONE_NUMBER, phoneNumber);
        log.telephoneNumber = phoneNumber;
        callLogs.push_back(log);
    }
    helper->Release();
    return ERR_OK;
}

static bool WriteToAshmem(MessageParcel &tempParcel, size_t dataSize, MessageParcel &reply)
{
    EDMLOGI("GetCallLogsPlugin: data size too large, use ashmem");
    std::string ashmemName;
    {
        std::lock_guard<std::mutex> lock(ashmemMutex_);
        ashmemName = CALL_LOG_ASHMEM_NAME + std::to_string(ashmemNum_++);
    }
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(ashmemName.c_str(), dataSize);
    if (ashmem == nullptr) {
        EDMLOGE("GetCallLogsPlugin: CreateAshmem failed.");
        return false;
    }
    if (!ashmem->MapReadAndWriteAshmem()) {
        EDMLOGE("GetCallLogsPlugin: MapReadAndWriteAshmem failed.");
        return false;
    }
    if (!ashmem->WriteToAshmem(reinterpret_cast<const void *>(tempParcel.GetData()), dataSize, 0)) {
        EDMLOGE("GetCallLogsPlugin: WriteToAshmem failed.");
        return false;
    }
    if (!reply.WriteInt32(ERR_OK)) {
        EDMLOGE("GetCallLogsPlugin: Write ERR_OK to reply failed.");
        return false;
    }
    if (!reply.WriteInt32(static_cast<int32_t>(dataSize))) {
        EDMLOGE("GetCallLogsPlugin: Write dataSize to reply failed.");
        return false;
    }
    if (!reply.WriteAshmem(ashmem)) {
        EDMLOGE("GetCallLogsPlugin: WriteAshmem to reply failed.");
        return false;
    }
    return true;
}

static bool WriteCallLogsToReply(std::vector<CallLogInfo> &callLogs, MessageParcel &reply)
{
    MessageParcel tempParcel;
    tempParcel.SetMaxCapacity(EdmConstants::MAX_PARCEL_CAPACITY_OF_ASHMEM);
    if (!tempParcel.WriteInt32(0)) {
        EDMLOGE("GetCallLogsPlugin: Write count placeholder failed.");
        return false;
    }
    int32_t actualCount = 0;
    for (const auto &log : callLogs) {
        if (tempParcel.GetDataSize() > EdmConstants::MAX_PARCEL_CAPACITY) {
            EDMLOGI("GetCallLogsPlugin: Data size exceeds limit, truncated at %{public}d records.", actualCount);
            break;
        }
        if (!tempParcel.WriteInt64(log.startTime) ||
            !tempParcel.WriteInt64(log.endTime) ||
            !tempParcel.WriteBool(log.isIncoming) ||
            !tempParcel.WriteInt32(log.slotId) ||
            !tempParcel.WriteString(log.telephoneNumber)) {
            EDMLOGE("GetCallLogsPlugin: Write record failed at index %{public}d.", actualCount);
            break;
        }
        actualCount++;
    }
    uint8_t *dataPtr = reinterpret_cast<uint8_t *>(tempParcel.GetData());
    if (dataPtr != nullptr) {
        *(reinterpret_cast<int32_t *>(dataPtr)) = actualCount;
    }
    size_t dataSize = tempParcel.GetDataSize();
    if (dataSize > EdmConstants::MAX_IPC_RAWDATA_SIZE) {
        return WriteToAshmem(tempParcel, dataSize, reply);
    }
    if (!reply.WriteInt32(ERR_OK)) {
        EDMLOGE("GetCallLogsPlugin: Write ERR_OK failed.");
        return false;
    }
    if (!reply.WriteInt32(static_cast<int32_t>(dataSize))) {
        EDMLOGE("GetCallLogsPlugin: Write dataSize failed.");
        return false;
    }
    return reply.WriteRawData(reinterpret_cast<const void *>(tempParcel.GetData()), dataSize);
}
#endif

ErrCode GetCallLogsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("GetCallLogsPlugin OnGetPolicy.");
#ifdef TELEPHONY_EDM_ENABLE
    TelephonyQueryConfig config;
    config.startTime = data.ReadInt64();
    config.endTime = data.ReadInt64();
    config.hasTelephoneNumber = data.ReadBool();
    if (config.hasTelephoneNumber) {
        config.telephoneNumber = data.ReadString();
    }
    if (config.startTime < 0 || config.endTime < 0 || config.startTime > config.endTime) {
        EDMLOGE("GetCallLogsPlugin: Invalid time range.");
        reply.WriteInt32(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (config.endTime - config.startTime > MAX_TIME_RANGE_MILLIS) {
        EDMLOGE("GetCallLogsPlugin: Time range exceeds 31 days.");
        reply.WriteInt32(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (config.hasTelephoneNumber && config.telephoneNumber.empty()) {
        EDMLOGE("GetCallLogsPlugin: telephoneNumber is empty.");
        reply.WriteInt32(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    std::vector<CallLogInfo> callLogs;
    ErrCode queryRet = QueryCallLogs(config, callLogs);
    if (queryRet != ERR_OK) {
        reply.WriteInt32(queryRet);
        return queryRet;
    }
    if (!WriteCallLogsToReply(callLogs, reply)) {
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    EDMLOGI("GetCallLogsPlugin OnGetPolicy success, count = %{public}zu.", callLogs.size());
    return ERR_OK;
#else
    EDMLOGW("GetCallLogsPlugin::OnGetPolicy Unsupported Capabilities.");
    reply.WriteInt32(EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}
} // namespace EDM
} // namespace OHOS
