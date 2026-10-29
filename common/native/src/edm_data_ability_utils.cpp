/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "edm_data_ability_utils.h"

#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "system_ability_definition.h"
#include "uri.h"

namespace OHOS {
namespace EDM {
const std::string SETTINGS_DATA_FIELD_KEYWORD = "KEYWORD";
const std::string SETTINGS_DATA_FIELD_VALUE = "VALUE";
constexpr const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
const std::string SETTINGS_DATA_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
constexpr const char *SMS_MMS_INFO_URI = "datashare:///com.ohos.smsmmsability/sms_mms/sms_mms_info";
constexpr const char *SMS_MMS_EXT_URI = "datashare:///com.ohos.smsmmsability";
const std::string SMS_FIELD_TIME = "start_time";
const std::string SMS_FIELD_IS_SENDER = "is_sender";
const std::string SMS_FIELD_SLOT_ID = "slot_id";
const std::string SMS_FIELD_CONTENT = "msg_content";
const std::string SMS_FIELD_RECEIVER_NUMBER = "receiver_number";

ErrCode EdmDataAbilityUtils::GetStringFromSettingsDataShare(const std::string &key, std::string &value)
{
    return GetStringFromSettingsDataShare(SETTINGS_DATA_BASE_URI, key, value);
}

ErrCode EdmDataAbilityUtils::GetIntFromSettingsDataShare(const std::string &key, int32_t &result)
{
    return GetIntFromSettingsDataShare(SETTINGS_DATA_BASE_URI, key, result);
}

ErrCode EdmDataAbilityUtils::UpdateSettingsData(const std::string &key, const std::string &value)
{
    return UpdateSettingsData(SETTINGS_DATA_BASE_URI, key, value);
}

ErrCode EdmDataAbilityUtils::GetStringFromSettingsDataShare(
    const std::string &strUri, const std::string &key, std::string &value)
{
    EDMLOGD("EdmDataAbilityUtils::GetStringFromSettingsDataShare enter.");
    sptr<IRemoteObject> remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    auto dataShareHelper = DataShare::DataShareHelper::Creator(remoteObject, strUri, SETTINGS_DATA_EXT_URI);
    if (dataShareHelper == nullptr) {
        EDMLOGE("EdmDataAbilityUtils::Acquire dataShareHelper failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    Uri uri(strUri);
    std::vector<std::string> columns{SETTINGS_DATA_FIELD_VALUE};
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_FIELD_KEYWORD, key);
    auto resultset = dataShareHelper->Query(uri, predicates, columns);
    if (resultset == nullptr) {
        EDMLOGE("EdmDataAbilityUtils::GetStringFromDataAbility query fail.");
        dataShareHelper->Release();
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t numRows = 0;
    resultset->GetRowCount(numRows);
    if (numRows <= 0) {
        EDMLOGD("EdmDataAbilityUtils::GetStringFromDataAbility row zero.");
        resultset->Close();
        dataShareHelper->Release();
        return ERR_OK;
    }
    int columnIndex = 0;
    resultset->GoToFirstRow();
    resultset->GetColumnIndex(SETTINGS_DATA_FIELD_VALUE, columnIndex);
    resultset->GetString(columnIndex, value);
    resultset->Close();
    dataShareHelper->Release();
    return ERR_OK;
}

ErrCode EdmDataAbilityUtils::GetIntFromSettingsDataShare(
    const std::string &strUri, const std::string &key, int32_t &result)
{
    std::string valueStr;
    if (FAILED(GetStringFromSettingsDataShare(strUri, key, valueStr))) {
        EDMLOGE("EdmDataAbilityUtils::GetIntFromSettingsDataShare fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (valueStr.empty()) {
        EDMLOGE("EdmDataAbilityUtils::GetIntFromSettingsDataShare empty.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    char* endptr;
    errno = 0;
    result = strtol(valueStr.c_str(), &endptr, EdmConstants::DECIMAL);
    if (errno == ERANGE || endptr == valueStr.c_str() || *endptr != '\0') {
        EDMLOGE("EdmDataAbilityUtils::GetIntFromSettingsDataShare strtol error.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode EdmDataAbilityUtils::UpdateSettingsData(
    const std::string &baseUri, const std::string &key, const std::string &value)
{
    sptr<IRemoteObject> remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    auto dataShareHelper = DataShare::DataShareHelper::Creator(remoteObject, baseUri, SETTINGS_DATA_EXT_URI);
    if (dataShareHelper == nullptr) {
        EDMLOGE("EdmDataAbilityUtils::Acquire dataShareHelper failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    EDMLOGD("UpdateSettingsData key = %{public}s", key.c_str());
    std::string strUri = baseUri + "&key=" + key;
    OHOS::Uri uri(strUri);
    OHOS::DataShare::DataShareValuesBucket bucket;
    bucket.Put(SETTINGS_DATA_FIELD_KEYWORD, key);
    bucket.Put(SETTINGS_DATA_FIELD_VALUE, value);

    OHOS::DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_FIELD_KEYWORD, key);

    std::vector<std::string> columns;
    columns.push_back(SETTINGS_DATA_FIELD_VALUE);
    auto resultset = dataShareHelper->Query(uri, predicates, columns);
    int numRows = 0;
    if (resultset == nullptr) {
        EDMLOGD("UpdateSettingsData nullptr Insert branch");
        dataShareHelper->Insert(uri, bucket);
        dataShareHelper->Release();
        return ERR_OK;
    }
    resultset->GetRowCount(numRows);
    resultset->Close();
    if (numRows <= 0) {
        EDMLOGD("UpdateSettingsData Insert branch");
        dataShareHelper->Insert(uri, bucket);
    } else {
        EDMLOGD("UpdateSettingsData Update branch");
        dataShareHelper->Update(uri, predicates, bucket);
    }
    dataShareHelper->Release();
    return ERR_OK;
}

static std::shared_ptr<DataShare::DataShareHelper> CreateSmsDataShareHelper()
{
    sptr<IRemoteObject> remoteObject =
        EdmSysManager::GetRemoteObjectOfSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    auto dataShareHelper = DataShare::DataShareHelper::Creator(remoteObject, SMS_MMS_INFO_URI, SMS_MMS_EXT_URI);
    if (dataShareHelper == nullptr) {
        EDMLOGE("EdmDataAbilityUtils::CreateSmsDataShareHelper acquire dataShareHelper failed.");
    }
    return dataShareHelper;
}

static DataShare::DataSharePredicates BuildSmsPredicates(int64_t startTime, int64_t endTime,
    const std::string &telephoneNumber)
{
    DataShare::DataSharePredicates predicates;
    predicates.GreaterThanOrEqualTo(SMS_FIELD_TIME, startTime)
        ->And()
        ->LessThanOrEqualTo(SMS_FIELD_TIME, endTime);
    if (!telephoneNumber.empty()) {
        predicates.And()->EqualTo(SMS_FIELD_RECEIVER_NUMBER, telephoneNumber);
    }
    return predicates;
}

static ErrCode ReadSmsMessagesFromResultSet(
    const std::shared_ptr<DataShare::DataShareResultSet> &resultset, std::vector<SmsQueryResult> &messages)
{
    int timeColumn = -1;
    int isSenderColumn = -1;
    int slotIdColumn = -1;
    int contentColumn = -1;
    int receiverNumberColumn = -1;
    resultset->GetColumnIndex(SMS_FIELD_TIME, timeColumn);
    resultset->GetColumnIndex(SMS_FIELD_IS_SENDER, isSenderColumn);
    resultset->GetColumnIndex(SMS_FIELD_SLOT_ID, slotIdColumn);
    resultset->GetColumnIndex(SMS_FIELD_CONTENT, contentColumn);
    resultset->GetColumnIndex(SMS_FIELD_RECEIVER_NUMBER, receiverNumberColumn);
    int isSenderValue = 0;
    int ret = resultset->GoToFirstRow();
    while (ret == 0) {
        SmsQueryResult info;
        resultset->GetLong(timeColumn, info.timer);
        resultset->GetInt(isSenderColumn, isSenderValue);
        info.isSender = (isSenderValue != 0);
        resultset->GetInt(slotIdColumn, info.slotId);
        resultset->GetString(contentColumn, info.content);
        resultset->GetString(receiverNumberColumn, info.telephoneNumber);
        messages.push_back(info);
        ret = resultset->GoToNextRow();
    }
    return ERR_OK;
}

ErrCode EdmDataAbilityUtils::GetSmsMessages(int64_t startTime, int64_t endTime,
    const std::string &telephoneNumber, std::vector<SmsQueryResult> &messages)
{
    EDMLOGI("EdmDataAbilityUtils::GetSmsMessages enter.");
    auto dataShareHelper = CreateSmsDataShareHelper();
    if (dataShareHelper == nullptr) {
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    Uri uri(SMS_MMS_INFO_URI);
    std::vector<std::string> columns{SMS_FIELD_TIME, SMS_FIELD_IS_SENDER, SMS_FIELD_SLOT_ID,
        SMS_FIELD_CONTENT, SMS_FIELD_RECEIVER_NUMBER};
    auto predicates = BuildSmsPredicates(startTime, endTime, telephoneNumber);
    auto resultset = dataShareHelper->Query(uri, predicates, columns);
    if (resultset == nullptr) {
        EDMLOGE("EdmDataAbilityUtils::GetSmsMessages query fail.");
        dataShareHelper->Release();
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    int32_t numRows = 0;
    resultset->GetRowCount(numRows);
    EDMLOGI("EdmDataAbilityUtils::GetSmsMessages row count=%{public}d", numRows);
    if (numRows <= 0) {
        resultset->Close();
        dataShareHelper->Release();
        return ERR_OK;
    }
    ErrCode ret = ReadSmsMessagesFromResultSet(resultset, messages);
    resultset->Close();
    dataShareHelper->Release();
    return ret;
}
} // namespace EDM
} // namespace OHOS
