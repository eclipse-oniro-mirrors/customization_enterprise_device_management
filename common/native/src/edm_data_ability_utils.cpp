/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "abs_shared_result_set.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "edm_data_ability_utils.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "system_ability_definition.h"
#include "uri.h"

namespace OHOS {
namespace EDM {
const std::string SETTINGS_DATA_FIELD_KEYWORD = "KEYWORD";
const std::string SETTINGS_DATA_FIELD_VALUE = "VALUE";

ErrCode EdmDataAbilityUtils::GetStringFromDataShare(const std::string &dataBaseUri,
    const std::string &key, std::string &value)
{
    EDMLOGI("EdmDataAbilityUtils::GetStringFromDataShareHelper enter.");
    sptr<IRemoteObject> remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    auto dataShareHelper = DataShare::DataShareHelper::Creator(remoteObject, dataBaseUri);
    if (dataShareHelper == nullptr) {
        EDMLOGE("EdmDataAbilityUtils::Acquire dataShareHelper failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    Uri uri(dataBaseUri);
    std::vector<std::string> columns{SETTINGS_DATA_FIELD_VALUE};
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_FIELD_KEYWORD, key);
    auto resultset = dataShareHelper->Query(uri, predicates, columns);
    if (resultset == nullptr) {
        EDMLOGE("EdmDataAbilityUtils::GetStringFromDataAbility query fail.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t numRows = 0;
    resultset->GetRowCount(numRows);
    if (numRows <= 0) {
        EDMLOGD("EdmDataAbilityUtils::GetStringFromDataAbility row zero.");
        return ERR_OK;
    }
    int columnIndex = 0;
    resultset->GoToFirstRow();
    resultset->GetColumnIndex(SETTINGS_DATA_FIELD_VALUE, columnIndex);
    resultset->GetString(columnIndex, value);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
