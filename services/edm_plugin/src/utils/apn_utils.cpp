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

#include "apn_utils.h"

#include <algorithm>
#include "edm_errors.h"
#include "edm_log.h"
#include "pdp_profile_data.h"
#include "core_service_client.h"
#include "edm_sys_manager.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {
namespace {
constexpr const char *PDP_PROFILE_BASE_URI = "datashare:///com.ohos.pdpprofileability";
constexpr const char *PDP_PROFILE_URI = "datashare:///com.ohos.pdpprofileability/net/pdp_profile";
constexpr const char *OPKEY_URI = "datashare:///com.ohos.pdpprofileability/opkey/opkey_info";
}

std::shared_ptr<DataShare::DataShareHelper> ApnUtils::CreateDataAbilityHelper()
{
    EDMLOGI("Create data ability helper");
    sptr<IRemoteObject> remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    return DataShare::DataShareHelper::Creator(remoteObject, PDP_PROFILE_BASE_URI);
}

int32_t ApnUtils::GetOpkey(const std::string &mccmnc, std::string &opkey)
{
    EDMLOGI("ApnUtils::GetOpkey start");
    auto helper = CreateDataAbilityHelper();
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo("mccmnc", mccmnc);
    Uri uri((OPKEY_URI));
    std::vector<std::string> columns;
    std::shared_ptr<DataShare::DataShareResultSet> queryResult = helper->Query(uri, predicates, columns);
    if (queryResult == nullptr) {
        EDMLOGE("GetOpkey error");
        return -1;
    }

    if (queryResult->GoToRow(0) != DataShare::E_OK) {
        EDMLOGE("GetOpkey GoToRow error");
        queryResult->Close();
        return -1;
    }

    int32_t columnIndex = -1;
    if (queryResult->GetColumnIndex("mccmnc", columnIndex) != DataShare::E_OK ||
        queryResult->GetString(columnIndex, opkey) != DataShare::E_OK) {
        return -1;
    }
    return 0;
}

int32_t ApnUtils::ApnInsert(const std::map<std::string, std::string> &apnInfo)
{
    EDMLOGI("ApnUtils::ApnInsert start");
    auto helper = CreateDataAbilityHelper();
    DataShare::DataShareValuesBucket values;
    for (const auto & [key, value] : apnInfo) {
        values.Put(key, value);
    }
    std::string mccmnc = apnInfo.at("mcc") + apnInfo.at("mnc");
    values.Put("mccmnc", mccmnc);
    std::string opkey;
    if (GetOpkey(mccmnc, opkey) != ERR_OK) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    values.Put("opkey", opkey);
    Uri uri((PDP_PROFILE_URI));
    return helper->Insert(uri, values) >= DataShare::E_OK ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

int32_t ApnUtils::ApnDelete(const std::string &apnId)
{
    EDMLOGI("ApnUtils::ApnDelete start");
    auto helper = CreateDataAbilityHelper();
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(Telephony::PdpProfileData::PROFILE_ID, apnId);
    Uri uri((PDP_PROFILE_URI));
    return helper->Delete(uri, predicates) == DataShare::E_OK ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

int32_t ApnUtils::ApnUpdate(const std::map<std::string, std::string> &apnInfo, const std::string &apnId)
{
    EDMLOGI("ApnUtils::ApnUpdate start");
    auto helper = CreateDataAbilityHelper();
    DataShare::DataShareValuesBucket values;
    for (const auto & [key, value] : apnInfo) {
        values.Put(key, value);
    }
    if (apnInfo.find("mcc") != apnInfo.end() || apnInfo.find("mnc") != apnInfo.end()) {
        std::string mccmnc;
        if (apnInfo.find("mcc") != apnInfo.end() && apnInfo.find("mnc") != apnInfo.end()) {
            mccmnc = apnInfo.at("mcc") + apnInfo.at("mnc");
        } else if (apnInfo.find("mcc") != apnInfo.end()) {
            mccmnc = apnInfo.at("mcc") + ApnQuery(apnId)["mnc"];
        } else {
            mccmnc = ApnQuery(apnId)["mcc"] + apnInfo.at("mnc");
        }
        values.Put("mccmnc", mccmnc);
    }
    std::string opkey;
    if (GetOpkey(mccmnc, opkey) != ERR_OK) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    values.Put("opkey", opkey);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(Telephony::PdpProfileData::PROFILE_ID, apnId);
    Uri uri((PDP_PROFILE_URI));
    return helper->Update(uri, predicates, values) == DataShare::E_OK ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

std::vector<std::string> ApnUtils::ApnQuery(const std::map<std::string, std::string> &apnInfo)
{
    EDMLOGI("ApnUtils::ApnQueryId start");
    auto helper = CreateDataAbilityHelper();
    std::vector<std::string> result;
    ApnQueryVector(helper, apnInfo, result);
    return result;
}

void ApnUtils::ApnQueryVector(std::shared_ptr<DataShare::DataShareHelper> helper,
    const std::map<std::string, std::string> &apnInfo, std::vector<std::string> &result)
{
    std::vector<std::string> columns;
    DataShare::DataSharePredicates predicates;
    for (const auto & [key, value] : apnInfo) {
        predicates.EqualTo(key, value);
    }
    Uri uri((PDP_PROFILE_URI));
    std::shared_ptr<DataShare::DataShareResultSet> queryResult = helper->Query(uri, predicates, columns);
    if (queryResult == nullptr) {
        EDMLOGE("QueryApnId error");
        return;
    }
    int32_t rowCnt = 0;
    queryResult->GetRowCount(rowCnt);
    for (int32_t rowIdx = 0; rowIdx < rowCnt; ++rowIdx) {
        if (queryResult->GoToRow(rowIdx)) {
            EDMLOGE("ApnQueryVector GoToRow error");
            queryResult->Close();
            return;
        }
        int32_t apnIdIdx = -1;
        queryResult->GetColumnIndex(Telephony::PdpProfileData::PROFILE_ID, apnIdIdx);
        int32_t apnId = -1;
        queryResult->GetInt(apnIdIdx, apnId);
        bool needInsert = !std::any_of(result.begin(), result.end(), [apnId](const auto &ele) {
            return ele == std::to_string(apnId);
        });
        if (needInsert) {
            result.push_back(std::to_string(apnId));
        }
    }
    queryResult->Close();
}

std::map<std::string, std::string> ApnUtils::ApnQuery(const std::string &apnId)
{
    EDMLOGI("ApnUtils::ApnQueryInfo start");
    auto helper = CreateDataAbilityHelper();

    std::map<std::string, std::string> results;
    int32_t queryResult = ApnQueryResultSet(helper, apnId, results);
    if (queryResult < 0) {
        EDMLOGE("QueryApnInfo error");
        return {};
    }

    return results;
}

int32_t ApnUtils::ApnQueryResultSet(std::shared_ptr<DataShare::DataShareHelper> helper, const std::string &apnId,
    std::map<std::string, std::string> &results)
{
    std::vector<std::string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(Telephony::PdpProfileData::PROFILE_ID, apnId);
    std::shared_ptr<DataShare::DataShareResultSet> queryResult = helper->Query(uri, predicates, columns);
    if (queryResult == nullptr) {
        EDMLOGE("QueryApnResultSet error");
        return -1;
    }
    
    int32_t rowCnt = 0;
    queryResult->GetRowCount(rowCnt);
    EDMLOGI("ApnQuery rowCnt: %{public}d", rowCnt);
    if (rowCnt <= 0) {
        queryResult->Close();
        return ERR_OK;
    }

    if (queryResult->GoToRow(0) != DataShare::E_OK) {
        EDMLOGE("ApnQuery GoToRow error");
        queryResult->Close();
        return -1;
    }
    int32_t columnCnt = -1;
    queryResult->GetColumnCount(columnCnt);
    for (int32_t idx = 0; idx < columnCnt; ++idx) {
        std::string columnName;
        queryResult->GetColumnName(idx, columnName);
        DataShare::DataType dataType;
        queryResult->GetDataType(idx, dataType);
        if (dataType == DataShare::DataType::TYPE_INTEGER) {
            int32_t value;
            queryResult->GetInt(idx, value);
            results[columnName] = std::to_string(value);
        } else if (dataType == DataShare::DataType::TYPE_STRING) {
            queryResult->GetString(idx, results[columnName]);
        }
    }
    queryResult->Close();
    return ERR_OK;
}

int32_t ApnUtils::ApnSetPrefer(const std::string &apnId)
{
    EDMLOGI("ApnUtils::ApnSetPrefer start");
    char* pResult = nullptr;
    const int32_t apnIdInt = static_cast<int32_t>(std::strtol(apnId.c_str(), &pResult, 10));
    if (apnId.c_str() == pResult) {
        EDMLOGE("ApnUtils::ApnSetPrefer failed to convert type");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return Telephony::CellularDataClient::GetInstance().SetPreferApn(apnIdInt) == DataShare::E_OK ? ERR_OK :
        EdmReturnErrCode::SYSTEM_ABNORMALLY;
}
} // namespace EDM
} // namespace OHOS