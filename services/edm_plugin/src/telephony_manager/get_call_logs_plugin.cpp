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
constexpr const char *CALL_LOG_BASE_URI = "datashare:///com.ohos.calllogability";
constexpr const char *CALL_LOG_URI = "datashare:///com.ohos.calllogability/calls/calllog";
constexpr const char *CALL_LOG_COLUMN_ID = "id";
constexpr const char *CALL_LOG_COLUMN_PHONE_NUMBER = "phone_number";
constexpr const char *CALL_LOG_COLUMN_CREATE_TIME = "create_time";
constexpr const char *CALL_LOG_COLUMN_BEGIN_TIME = "begin_time";
constexpr const char *CALL_LOG_COLUMN_END_TIME = "end_time";
constexpr const char *CALL_LOG_COLUMN_CALL_DIRECTION = "call_direction";
constexpr const char *CALL_LOG_COLUMN_SLOT_ID = "slot_id";
constexpr int32_t CALL_DIRECTION_IN = 0;
constexpr int32_t CALL_DIRECTION_OUT = 1;
constexpr int32_t ROW_FETCH_SUCCESS = 0;
constexpr size_t ESTIMATED_RECORD_SIZE = 64;
constexpr int64_t ONE_DAY_SECONDS = 24LL * 60 * 60;
constexpr int64_t MAX_TIME_RANGE_SECONDS = 31LL * ONE_DAY_SECONDS;
constexpr int64_t MAX_CALL_LOG_RETURN_SIZE = 128LL * 1024 * 1024;
constexpr int32_t DATASHARE_WAIT_TIME = 10;
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
    return DataShare::DataShareHelper::Creator(remote, std::string(CALL_LOG_BASE_URI), "", DATASHARE_WAIT_TIME);
}

static DataShare::DataSharePredicates BuildPredicates(const TelephonyQueryConfig &config)
{
    DataShare::DataSharePredicates predicates;
    predicates.GreaterThanOrEqualTo(CALL_LOG_COLUMN_CREATE_TIME, std::to_string(config.startTime));
    predicates.And()->LessThanOrEqualTo(CALL_LOG_COLUMN_CREATE_TIME, std::to_string(config.endTime));
    if (config.hasTelephoneNumber && !config.telephoneNumber.empty()) {
        predicates.And()->EqualTo(CALL_LOG_COLUMN_PHONE_NUMBER, config.telephoneNumber);
    }
    predicates.OrderByDesc(CALL_LOG_COLUMN_CREATE_TIME);
    return predicates;
}

static std::vector<std::string> BuildResultColumns()
{
    return {
        CALL_LOG_COLUMN_ID,
        CALL_LOG_COLUMN_CREATE_TIME,
        CALL_LOG_COLUMN_PHONE_NUMBER,
        CALL_LOG_COLUMN_BEGIN_TIME,
        CALL_LOG_COLUMN_END_TIME,
        CALL_LOG_COLUMN_CALL_DIRECTION,
        CALL_LOG_COLUMN_SLOT_ID,
    };
}

static void ReadCallLogFromResultSet(
    std::shared_ptr<DataShare::DataShareResultSet> resultSet, CallLogInfo &log)
{
    int32_t columnIndex = 0;
    int64_t createTime = 0;
    resultSet->GetColumnIndex(CALL_LOG_COLUMN_CREATE_TIME, columnIndex);
    resultSet->GetLong(columnIndex, createTime);
    log.createTime = createTime;
    int64_t beginTime = 0;
    resultSet->GetColumnIndex(CALL_LOG_COLUMN_BEGIN_TIME, columnIndex);
    resultSet->GetLong(columnIndex, beginTime);
    log.startTime = beginTime;
    resultSet->GetColumnIndex(CALL_LOG_COLUMN_END_TIME, columnIndex);
    int64_t endTime = 0;
    resultSet->GetLong(columnIndex, endTime);
    log.endTime = endTime;
    int32_t callDirection = CALL_DIRECTION_OUT;
    resultSet->GetColumnIndex(CALL_LOG_COLUMN_CALL_DIRECTION, columnIndex);
    resultSet->GetInt(columnIndex, callDirection);
    log.isIncoming = (callDirection == CALL_DIRECTION_IN);
    int32_t slotId = -1;
    resultSet->GetColumnIndex(CALL_LOG_COLUMN_SLOT_ID, columnIndex);
    resultSet->GetInt(columnIndex, slotId);
    log.slotId = slotId;
    std::string phoneNumber;
    resultSet->GetColumnIndex(CALL_LOG_COLUMN_PHONE_NUMBER, columnIndex);
    resultSet->GetString(columnIndex, phoneNumber);
    log.telephoneNumber = phoneNumber;
}

static ErrCode QueryCallLogs(const TelephonyQueryConfig &config, std::vector<CallLogInfo> &callLogs)
{
    auto helper = CreateCallLogHelper();
    if (helper == nullptr) {
        EDMLOGE("GetCallLogsPlugin: CreateCallLogHelper failed.");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    auto predicates = BuildPredicates(config);
    auto columns = BuildResultColumns();
    Uri uri(CALL_LOG_URI);
    auto resultSet = helper->Query(uri, predicates, columns);
    if (resultSet == nullptr) {
        EDMLOGE("GetCallLogsPlugin: Query call log failed.");
        helper->Release();
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    int32_t rowCount = 0;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        EDMLOGI("GetCallLogsPlugin: Query success, but rowCount is 0.");
        resultSet->Close();
        helper->Release();
        return ERR_OK;
    }
    int32_t operationResult = resultSet->GoToFirstRow();
    while (operationResult == ROW_FETCH_SUCCESS) {
        if (callLogs.size() * ESTIMATED_RECORD_SIZE >= MAX_CALL_LOG_RETURN_SIZE) {
            EDMLOGI("GetCallLogsPlugin: Estimated data size exceeds limit, stop at %{public}zu records.",
                callLogs.size());
            break;
        }
        CallLogInfo log;
        ReadCallLogFromResultSet(resultSet, log);
        callLogs.push_back(log);
        operationResult = resultSet->GoToNextRow();
    }
    resultSet->Close();
    helper->Release();
    EDMLOGI("GetCallLogsPlugin: QueryCallLogs success, count = %{public}zu.", callLogs.size());
    return ERR_OK;
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
        if (tempParcel.GetDataSize() > MAX_CALL_LOG_RETURN_SIZE) {
            EDMLOGI("GetCallLogsPlugin: Data size exceeds limit, truncated at %{public}d records.", actualCount);
            break;
        }
        if (!tempParcel.WriteInt64(log.createTime) ||
            !tempParcel.WriteInt64(log.startTime) ||
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
    if (!reply.WriteInt32(static_cast<int32_t>(dataSize))) {
        EDMLOGE("GetCallLogsPlugin: Write dataSize failed.");
        return false;
    }
    if (!reply.WriteRawData(reinterpret_cast<const void *>(tempParcel.GetData()), dataSize)) {
        EDMLOGE("GetCallLogsPlugin: WriteRawData failed, dataSize = %{public}zu.", dataSize);
        return false;
    }
    return true;
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
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (config.endTime - config.startTime > MAX_TIME_RANGE_SECONDS) {
        EDMLOGE("GetCallLogsPlugin: Time range exceeds 31 days.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (config.hasTelephoneNumber && config.telephoneNumber.empty()) {
        EDMLOGE("GetCallLogsPlugin: telephoneNumber is empty.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    std::vector<CallLogInfo> callLogs;
    ErrCode queryRet = QueryCallLogs(config, callLogs);
    if (queryRet != ERR_OK) {
        EDMLOGE("GetCallLogsPlugin: QueryCallLogs failed, ret = %{public}d.", queryRet);
        return queryRet;
    }
    if (!WriteCallLogsToReply(callLogs, reply)) {
        EDMLOGE("GetCallLogsPlugin: WriteCallLogsToReply failed.");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    EDMLOGI("GetCallLogsPlugin OnGetPolicy success, count = %{public}zu.", callLogs.size());
    return ERR_OK;
#else
    EDMLOGW("GetCallLogsPlugin::OnGetPolicy Unsupported Capabilities.");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
#endif
}
} // namespace EDM
} // namespace OHOS
