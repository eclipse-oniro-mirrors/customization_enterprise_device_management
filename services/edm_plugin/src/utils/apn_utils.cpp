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
#include "edm_sys_manager.h"
#include "system_ability_definition.h"
#include "pdp_profile_data.h"
#include "core_manager_inner.h"

namespace OHOS {
namespace EDM {
namespace {
constexpr const char *PDP_PROFILE_BASE_URI = "datashare:///com.ohos.pdpprofileability";
constexpr const char *PDP_PROFILE_URI = "datashare:///com.ohos.pdpprofileability/net/pdp_profile";
constexpr int32_t SIM_SLOT_ZERO_ID = 0;
constexpr int32_t SIM_SLOT_ONE_ID = 1;
}

std::shared_ptr<DataShare::DataShareHelper> ApnUtils::CreateDataAbilityHelper()
{
    EDMLOGI("Create data ability helper");
    sptr<IRemoteObject> remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    return DataShare::DataShareHelper::Creator(remoteObject, PDP_PROFILE_BASE_URI);
}

int32_t ApnUtils::ApnInsert(const std::map<std::string, std::string> &apnInfo)
{
    EDMLOGI("ApnUtils::ApnInsert start");
    auto helper = CreateDataAbilityHelper();
    DataShare::DataShareValuesBucket values;
    std::map<std::string, std::string> apnInfoTmp = apnInfo;
    if (apnInfo.find("opkey") == apnInfo.end() || apnInfo.at("opkey") == "") {
        std::string opkey = system::GetParameter("telephony.sim.opkey", "");
        if (opkey.empty()) {
            return -1;
        }
        apnInfoTmp["opkey"] = opkey;
    }
    for (auto & [key, value] : apnInfoTmp) {
        values.Put(key, value);
    }
    Uri uri(PDP_PROFILE_URI);
    return helper->Insert(uri, values);
}

int32_t ApnUtils::ApnDelete(const std::string &apnId)
{
    EDMLOGI("ApnUtils::ApnDelete start");
    auto helper = CreateDataAbilityHelper();
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(Telephony::PdpProfileData::PROFILE_ID, apnId);
    Uri uri(PDP_PROFILE_URI);
    return helper->Delete(uri, predicates);
}

int32_t ApnUtils::ApnUpdate(const std::map<std::string, std::string> &apnInfo, const std::string &apnId)
{
    EDMLOGI("ApnUtils::ApnUpdate start");
    auto helper = CreateDataAbilityHelper();
    DataShare::DataShareValuesBucket values;
    for (auto & [key, value] : apnInfo) {
        values.Put(key, value);
    }
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(Telephony::PdpProfileData::PROFILE_ID, apnId);
    Uri uri(PDP_PROFILE_URI);
    return helper->Update(uri, predicates, values);
}

std::vector<std::string> ApnUtils::ApnQuery(const std::map<std::string, std::string> &apnInfo)
{
    EDMLOGI("ApnUtils::ApnQueryId start");
    auto helper = CreateDataAbilityHelper();
    std::vector<std::string> result;
    ApnQueryVector(helper, SIM_SLOT_ZERO_ID, apnInfo, result);
    ApnQueryVector(helper, SIM_SLOT_ONE_ID, apnInfo, result);
    return result;
}

void ApnUtils::ApnQueryVector(std::shared_ptr<DataShare::DataShareHelper> helper, int32_t slotId,
    const std::map<std::string, std::string> &apnInfo, std::vector<std::string> &result)
{
    std::vector<std::string> columns;
    DataShare::DataSharePredicates predicates;
    for (auto & [key, value] : apnInfo) {
        predicates.EqualTo(key, value);
    }
    int32_t simId = Telephony::CoreManagerInner::GetInstance().GetSimId(slotId);
    Uri uri(std::string(PDP_PROFILE_URI) + "?simId=" + std::to_string(simId));
    std::shared_ptr<DataShare::DataShareResultSet> queryResult = helper->Query(uri, predicates, columns);
    if (queryResult == nullptr) {
        EDMLOGE("QueryApnId error");
        return;
    }
    int32_t rowCnt = 0;
    queryResult->GetRowCount(rowCnt);
    for (int32_t rowIdx = 0; rowIdx < rowCnt; ++rowIdx) {
        queryResult->GoToRow(rowIdx);
        int32_t apnIdIdx = -1;
        queryResult->GetColumnIndex(Telephony::PdpProfileData::PROFILE_ID, apnIdIdx);
        int32_t apnId = -1;
        queryResult->GetInt(apnIdIdx, apnId);
        result.push_back(std::to_string(apnId));
    }
}

std::map<std::string, std::string> ApnUtils::ApnQuery(const std::string &apnId)
{
    EDMLOGI("ApnUtils::ApnQueryInfo start");
    auto helper = CreateDataAbilityHelper();

    std::shared_ptr<DataShare::DataShareResultSet> queryResult = nullptr;
    if ((queryResult = ApnQueryResultSet(helper, SIM_SLOT_ZERO_ID, apnId)) ||
        (queryResult = ApnQueryResultSet(helper, SIM_SLOT_ONE_ID, apnId))) {
        return {};
    }

    std::map<std::string, std::string> result;
    queryResult->GoToRow(0);
    int32_t columnCnt = -1;
    queryResult->GetColumnCount(columnCnt);
    for (int32_t idx = 0; idx < columnCnt; ++idx) {
        std::string columnName;
        queryResult->GetColumnName(idx, columnName);
        queryResult->GetString(idx, result[columnName]);
    }
    return result;
}

std::shared_ptr<DataShare::DataShareResultSet> ApnUtils::ApnQueryResultSet(
    std::shared_ptr<DataShare::DataShareHelper> helper, int32_t slotId, const std::string &apnId)
{
    std::vector<std::string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(Telephony::PdpProfileData::PROFILE_ID, apnId);

    int32_t simId = Telephony::CoreManagerInner::GetInstance().GetSimId(slotId);
    Uri uri(std::string(PDP_PROFILE_URI) + "?simId=" + std::to_string(simId));

    std::shared_ptr<DataShare::DataShareResultSet> queryResult = helper->Query(uri, predicates, columns);
    if (queryResult == nullptr) {
        EDMLOGE("QueryApnInfo error");
        return nullptr;
    }

    int32_t rowCnt = 0;
    queryResult->GetRowCount(rowCnt);
    EDMLOGI("ApnQuery rowCnt: %{public}d", rowCnt);
    if (!rowCnt) {
        return nullptr;
    }
    return queryResult;
}

int32_t ApnUtils::ApnSetPrefer(const std::string &apnId)
{
    EDMLOGI("ApnUtils::ApnSetPrefer start");
    return Telephony::CellularDataClient::GetInstance().SetPreferApn(std::stoi(apnId));
}
} // namespace EDM
} // namespace OHOS