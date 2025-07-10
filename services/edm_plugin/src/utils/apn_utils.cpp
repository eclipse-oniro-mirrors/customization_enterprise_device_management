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
#include "parameters.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "pdp_profile_data.h"
#include "core_service_client.h"
#include "edm_sys_manager.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {
using namespace Telephony;
namespace {
constexpr const char *PDP_PROFILE_BASE_URI = "datashare:///com.ohos.pdpprofileability";
constexpr const char *PDP_PROFILE_URI = "datashare:///com.ohos.pdpprofileability/net/pdp_profile";
constexpr const char *PDP_PROFILE_PREFER_URI = "datashare:///com.ohos.pdpprofileability/net/pdp_profile/preferapn";
constexpr const char *OPKEY_BASE_URI = "datashare:///com.ohos.opkeyability";
constexpr const char *OPKEY_URI = "datashare:///com.ohos.opkeyability/opkey/opkey_info";
constexpr int32_t SIM_SLOT_ZERO = 0;
constexpr int32_t SIM_SLOT_ONE = 1;
}

std::shared_ptr<DataShare::DataShareHelper> ApnUtils::CreatePdpProfileAbilityHelper()
{
    EDMLOGI("Create pdp profile ability helper");
    sptr<IRemoteObject> remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    return DataShare::DataShareHelper::Creator(remoteObject, PDP_PROFILE_BASE_URI);
}

std::shared_ptr<DataShare::DataShareHelper> ApnUtils::CreateOpkeyAbilityHelper()
{
    EDMLOGI("Create opkey ability helper");
    sptr<IRemoteObject> remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    return DataShare::DataShareHelper::Creator(remoteObject, OPKEY_BASE_URI);
}

int32_t ApnUtils::GetOpkey(const std::string &mccmnc, std::string &opkey)
{
    EDMLOGI("ApnUtils::GetOpkey start");
    auto helper = CreateOpkeyAbilityHelper();
    if (helper == nullptr) {
        EDMLOGE("GetOpkey helper get failed");
        return -1;
    }
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PdpProfileData::MCCMNC, mccmnc);
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
    if (queryResult->GetColumnIndex("operator_key", columnIndex) != DataShare::E_OK ||
        queryResult->GetString(columnIndex, opkey) != DataShare::E_OK) {
        return -1;
    }
    EDMLOGI("ApnUtils::GetOpkey opkey=%{public}s", opkey.c_str());
    return 0;
}

int32_t ApnUtils::ApnInsert(const std::map<std::string, std::string> &apnInfo)
{
    EDMLOGI("ApnUtils::ApnInsert start");
    auto helper = CreatePdpProfileAbilityHelper();
    if (helper == nullptr) {
        EDMLOGE("ApnInsert helper get failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    DataShare::DataShareValuesBucket values;
    for (const auto & [key, value] : apnInfo) {
        values.Put(key, value);
    }
    std::string mccmnc = apnInfo.at(PdpProfileData::MCC) + apnInfo.at(PdpProfileData::MNC);
    values.Put(PdpProfileData::MCCMNC, mccmnc);
    std::string opkey;
    if (GetOpkey(mccmnc, opkey) == ERR_OK && !opkey.empty()) {
        values.Put(PdpProfileData::OPKEY, opkey);
    } else {
        values.Put(PdpProfileData::OPKEY, mccmnc);
    }
    Uri uri((PDP_PROFILE_URI));
    return helper->Insert(uri, values) >= DataShare::E_OK ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

int32_t ApnUtils::ApnDelete(const std::string &apnId)
{
    EDMLOGI("ApnUtils::ApnDelete start");
    auto helper = CreatePdpProfileAbilityHelper();
    if (helper == nullptr) {
        EDMLOGE("ApnDelete helper get failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PdpProfileData::PROFILE_ID, apnId);
    Uri uri((PDP_PROFILE_URI));
    return helper->Delete(uri, predicates) == DataShare::E_OK ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

int32_t ApnUtils::ApnUpdate(const std::map<std::string, std::string> &apnInfo, const std::string &apnId)
{
    EDMLOGI("ApnUtils::ApnUpdate start");
    auto helper = CreatePdpProfileAbilityHelper();
    if (helper == nullptr) {
        EDMLOGE("ApnUpdate helper get failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    DataShare::DataShareValuesBucket values;
    for (const auto & [key, value] : apnInfo) {
        values.Put(key, value);
    }

    std::string mccmnc;
    if (apnInfo.find(PdpProfileData::MCC) != apnInfo.end() && apnInfo.find(PdpProfileData::MNC) != apnInfo.end()) {
        mccmnc = apnInfo.at(PdpProfileData::MCC) + apnInfo.at(PdpProfileData::MNC);
    } else if (apnInfo.find(PdpProfileData::MCC) != apnInfo.end()) {
        mccmnc = apnInfo.at(PdpProfileData::MCC) + ApnQuery(apnId)[PdpProfileData::MNC];
    } else if (apnInfo.find(PdpProfileData::MNC) != apnInfo.end()) {
        mccmnc = ApnQuery(apnId)[PdpProfileData::MCC] + apnInfo.at(PdpProfileData::MNC);
    }

    if (apnInfo.find(PdpProfileData::MCC) != apnInfo.end() || apnInfo.find(PdpProfileData::MNC) != apnInfo.end()) {
        values.Put(PdpProfileData::MCCMNC, mccmnc);
        std::string opkey;
        if (GetOpkey(mccmnc, opkey) == ERR_OK && !opkey.empty()) {
            values.Put(PdpProfileData::OPKEY, opkey);
        } else {
            values.Put(PdpProfileData::OPKEY, mccmnc);
        }
    }
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PdpProfileData::PROFILE_ID, apnId);
    Uri uri((PDP_PROFILE_URI));
    return helper->Update(uri, predicates, values) == DataShare::E_OK ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

std::vector<std::string> ApnUtils::ApnQuery(const std::map<std::string, std::string> &apnInfo)
{
    EDMLOGI("ApnUtils::ApnQueryId start");
    auto helper = CreatePdpProfileAbilityHelper();
    std::vector<std::string> result;
    ApnQueryVector(helper, apnInfo, result);
    return result;
}

void ApnUtils::ApnQueryVector(std::shared_ptr<DataShare::DataShareHelper> helper,
    const std::map<std::string, std::string> &apnInfo, std::vector<std::string> &result)
{
    if (helper == nullptr) {
        EDMLOGE("ApnQueryVector helper get failed");
        return;
    }
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
        queryResult->GetColumnIndex(PdpProfileData::PROFILE_ID, apnIdIdx);
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
    auto helper = CreatePdpProfileAbilityHelper();

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
    if (helper == nullptr) {
        EDMLOGE("ApnQueryResultSet helper get failed");
        return -1;
    }
    std::vector<std::string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PdpProfileData::PROFILE_ID, apnId);
    Uri uri((PDP_PROFILE_URI));
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

int32_t ApnUtils::MatchValidSimId(const std::string &opkey, int32_t slotId)
{
    std::string sysOpkey = system::GetParameter(std::string("telephony.sim.opkey") + std::to_string(slotId), "");
    if (opkey != sysOpkey) {
        return -1;
    }
    if (!Telephony::CoreServiceClient::GetInstance().IsSimActive(slotId)) {
        return -1;
    }
    int32_t simId = Telephony::CoreServiceClient::GetInstance().GetSimId(slotId);
    if (simId < 0) {
        return -1;
    }
    return simId;
}

int32_t ApnUtils::GetValidSimId(const std::string &apnId)
{
    std::string opkey;
    if (GetOpkey(ApnQuery(apnId)[PdpProfileData::MCCMNC], opkey) != ERR_OK || opkey.empty()) {
        return -1;
    }

    int32_t simId = MatchValidSimId(opkey, SIM_SLOT_ZERO);
    if (simId >= 0) {
        return simId;
    }

    simId = MatchValidSimId(opkey, SIM_SLOT_ONE);
    if (simId >= 0) {
        return simId;
    }
    return -1;
}

int32_t ApnUtils::ApnSetPrefer(const std::string &apnId)
{
    EDMLOGI("ApnUtils::ApnSetPrefer start");

    auto helper = CreatePdpProfileAbilityHelper();
    if (helper == nullptr) {
        EDMLOGE("ApnSetPrefer helper get failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    int32_t simId = GetValidSimId(apnId);
    if (simId < 0) {
        EDMLOGE("ApnUtils::ApnSetPrefer get failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    char* pResult = nullptr;
    const int32_t apnIdInt = static_cast<int32_t>(std::strtol(apnId.c_str(), &pResult, 10));
    if (apnId.c_str() == pResult) {
        EDMLOGE("ApnUtils::ApnSetPrefer failed to convert type");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket values;
    double profileIdAsDouble = static_cast<double>(apnIdInt);
    double simIdAsDouble = static_cast<double>(simId);
    values.Put(PdpProfileData::PROFILE_ID, profileIdAsDouble);
    values.Put(PdpProfileData::SIM_ID, simIdAsDouble);
    Uri preferApnUri(PDP_PROFILE_PREFER_URI);
    int32_t result = helper->Update(preferApnUri, predicates, values);
    if (result < DataShare::E_OK) {
        EDMLOGE("SetPreferApn fail! result:%{public}d", result);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    EDMLOGI("SetPreferApn result:%{public}d", result);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS