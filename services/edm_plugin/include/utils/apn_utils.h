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

#ifndef SERVICES_EDM_INCLUDE_UTILS_APN_UTILS_H
#define SERVICES_EDM_INCLUDE_UTILS_APN_UTILS_H

#include <string>
#include <memory>
#include "datashare_helper.h"
#include "cellular_data_client.h"

namespace OHOS {
namespace EDM {
class ApnUtils {
public:
    static int32_t ApnInsert(const std::map<std::string, std::string> &apnInfo);
    static int32_t ApnDelete(const std::string &apnId);
    static int32_t ApnUpdate(const std::map<std::string, std::string> &apnInfo, const std::string &apnId);
    static std::vector<std::string> ApnQuery(const std::map<std::string, std::string> &apnInfo);
    static std::map<std::string, std::string> ApnQuery(const std::string &apnId);
    static int32_t ApnSetPrefer(const std::string &apnId);
private:
    static std::shared_ptr<DataShare::DataShareHelper> CreatePdpProfileAbilityHelper();
    static std::shared_ptr<DataShare::DataShareHelper> CreateOpkeyAbilityHelper();
    static int32_t ApnQueryResultSet(std::shared_ptr<DataShare::DataShareHelper> helper, const std::string &apnId,
        std::map<std::string, std::string> &results);
    static void ApnQueryVector(std::shared_ptr<DataShare::DataShareHelper> helper,
        const std::map<std::string, std::string> &apnInfo, std::vector<std::string> &result);
    static int32_t GetOpkey(const std::string &mccmnc, std::string &opkey);
    static int32_t MatchValidSimId(const std::string &apnId);
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_UTILS_APN_UTILS_H