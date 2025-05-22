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

namespace OHOS {
namespace EDM {
namespace {
constexpr const char *PDP_PROFILE_BASE_URI = "datashare:///com.ohos.pdpprofileability";
constexpr const char *PDP_PROFILE_URI = "datashare:///com.ohos.pdpprofileability/net/pdp_profile";
}

std::shared_ptr<DataShare::DataShareHelper> ApnUtils::CreateDataAbilityHelper()
{
    EDMLOGI("Create data ability helper");
    sptr<IRemoteObject> remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(TELEPHONY_SMS_MMS_SYS_ABILITY_ID);
    return DataShare::DataShareHelper::Creator(remoteObject, PDP_PROFILE_BASE_URI);
}

int ApnUtils::ApnInsert(const std::map<std::string, std::string> &apnInfo)
{
    auto helper = CreateDataAbilityHelper();
    DataShare::DataShareValuesBucket value;
    value.Put(Telephony::PdpProfileData::PROFILE_NAME,
        apnInfo.at(std::string(Telephony::PdpProfileData::PROFILE_NAME)));
    value.Put(Telephony::PdpProfileData::APN, apnInfo.at(std::string(Telephony::PdpProfileData::APN)));
    value.Put(Telephony::PdpProfileData::MCC, apnInfo.at(std::string(Telephony::PdpProfileData::MCC)));
    value.Put(Telephony::PdpProfileData::MNC, apnInfo.at(std::string(Telephony::PdpProfileData::MNC)));
    value.Put(Telephony::PdpProfileData::AUTH_USER, apnInfo.at(std::string(Telephony::PdpProfileData::AUTH_USER)));
    value.Put(Telephony::PdpProfileData::APN_TYPES, apnInfo.at(std::string(Telephony::PdpProfileData::APN_TYPES)));
    value.Put(Telephony::PdpProfileData::PROXY_IP_ADDRESS,
        apnInfo.at(std::string(Telephony::PdpProfileData::PROXY_IP_ADDRESS)));
    value.Put(Telephony::PdpProfileData::MMS_IP_ADDRESS,
        apnInfo.at(std::string(Telephony::PdpProfileData::MMS_IP_ADDRESS)));
    Uri uri(PDP_PROFILE_URI);
    return helper->Insert(uri, value);
}

int ApnUtils::ApnDelete(const std::string &apnId)
{
    auto helper = CreateDataAbilityHelper();
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(Telephony::PdpProfileData::PROFILE_ID, apnId);
    Uri uri(PDP_PROFILE_URI);
    return helper->Delete(uri, predicates);
}

int ApnUtils::ApnUpdate(const std::map<std::string, std::string> &apnInfo, const std::string &apnId)
{
    auto helper = CreateDataAbilityHelper();
    DataShare::DataShareValuesBucket value;
    value.Put(Telephony::PdpProfileData::PROFILE_NAME,
        apnInfo.at(std::string(Telephony::PdpProfileData::PROFILE_NAME)));
    value.Put(Telephony::PdpProfileData::APN, apnInfo.at(std::string(Telephony::PdpProfileData::APN)));
    value.Put(Telephony::PdpProfileData::MCC, apnInfo.at(std::string(Telephony::PdpProfileData::MCC)));
    value.Put(Telephony::PdpProfileData::MNC, apnInfo.at(std::string(Telephony::PdpProfileData::MNC)));
    value.Put(Telephony::PdpProfileData::AUTH_USER, apnInfo.at(std::string(Telephony::PdpProfileData::AUTH_USER)));
    value.Put(Telephony::PdpProfileData::APN_TYPES, apnInfo.at(std::string(Telephony::PdpProfileData::APN_TYPES)));
    value.Put(Telephony::PdpProfileData::PROXY_IP_ADDRESS,
        apnInfo.at(std::string(Telephony::PdpProfileData::PROXY_IP_ADDRESS)));
    value.Put(Telephony::PdpProfileData::MMS_IP_ADDRESS,
        apnInfo.at(std::string(Telephony::PdpProfileData::MMS_IP_ADDRESS)));
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(Telephony::PdpProfileData::PROFILE_ID, apnId);
    Uri uri(PDP_PROFILE_URI);
    return helper->Update(uri, predicates, value);
}

std::vector<std::string> ApnUtils::ApnQuery(const std::map<std::string, std::string> &apnInfo)
{
    std::vector<std::string> result;
    auto apnInfoEx = std::make_shared<Telephony::ApnInfo>();
    apnInfoEx->apnName = Str8ToStr16(apnInfo.at(std::string(Telephony::PdpProfileData::PROFILE_NAME)));
    apnInfoEx->apn = Str8ToStr16(apnInfo.at(std::string(Telephony::PdpProfileData::APN)));
    apnInfoEx->mcc = Str8ToStr16(apnInfo.at(std::string(Telephony::PdpProfileData::MCC)));
    apnInfoEx->mnc = Str8ToStr16(apnInfo.at(std::string(Telephony::PdpProfileData::MNC)));
    apnInfoEx->user = Str8ToStr16(apnInfo.at(std::string(Telephony::PdpProfileData::AUTH_USER)));
    apnInfoEx->type = Str8ToStr16(apnInfo.at(std::string(Telephony::PdpProfileData::APN_TYPES)));
    apnInfoEx->proxy = Str8ToStr16(apnInfo.at(std::string(Telephony::PdpProfileData::PROXY_IP_ADDRESS)));
    apnInfoEx->mmsproxy = Str8ToStr16(apnInfo.at(std::string(Telephony::PdpProfileData::MMS_IP_ADDRESS)));
    std::vector<uint32_t> apnIdList;
    Telephony::CellularDataClient::GetInstance().QueryApnIds(*apnInfoEx, apnIdList);
    std::transform(apnIdList.begin(), apnIdList.end(), std::back_inserter(result),
        [](uint32_t s) {
            return std::to_string(s);
        });
    return result;
}

std::map<std::string, std::string> ApnUtils::ApnQuery(const std::string &apnId)
{
    auto helper = CreateDataAbilityHelper();
    std::vector<std::string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(Telephony::PdpProfileData::PROFILE_ID, apnId);
    Uri uri(PDP_PROFILE_URI);
    std::shared_ptr<DataShare::DataShareResultSet> queryResult = helper->Query(uri, predicates, columns);
    if (queryResult == nullptr) {
        EDMLOGE("QueryAllApnInfo error");
        return {};
    }

    int rowCnt = 0;
    queryResult->GetRowCount(rowCnt);
    EDMLOGI("ApnQuery rowCnt: %{public}d", rowCnt);
    if (!rowCnt) {
        return {};
    }
    std::map<std::string, std::string> result;
    int index = 0;
    queryResult->GoToRow(0);
    queryResult->GetColumnIndex(Telephony::PdpProfileData::PROFILE_NAME, index);
    queryResult->GetString(index, result[Telephony::PdpProfileData::PROFILE_NAME]);
    queryResult->GetColumnIndex(Telephony::PdpProfileData::APN, index);
    queryResult->GetString(index, result[Telephony::PdpProfileData::APN]);
    queryResult->GetColumnIndex(Telephony::PdpProfileData::MCC, index);
    queryResult->GetString(index, result[Telephony::PdpProfileData::MCC]);
    queryResult->GetColumnIndex(Telephony::PdpProfileData::MNC, index);
    queryResult->GetString(index, result[Telephony::PdpProfileData::MNC]);
    queryResult->GetColumnIndex(Telephony::PdpProfileData::AUTH_USER, index);
    queryResult->GetString(index, result[Telephony::PdpProfileData::AUTH_USER]);
    queryResult->GetColumnIndex(Telephony::PdpProfileData::APN_TYPES, index);
    queryResult->GetString(index, result[Telephony::PdpProfileData::APN_TYPES]);
    queryResult->GetColumnIndex(Telephony::PdpProfileData::PROXY_IP_ADDRESS, index);
    queryResult->GetString(index, result[Telephony::PdpProfileData::PROXY_IP_ADDRESS]);
    queryResult->GetColumnIndex(Telephony::PdpProfileData::MMS_IP_ADDRESS, index);
    queryResult->GetString(index, result[Telephony::PdpProfileData::MMS_IP_ADDRESS]);
    return result;
}

int ApnUtils::ApnSetPrefer(const std::string &apnId)
{
    return Telephony::CellularDataClient::GetInstance().SetPreferApn(std::stoi(apnId));
}
} // namespace EDM
} // namespace OHOS