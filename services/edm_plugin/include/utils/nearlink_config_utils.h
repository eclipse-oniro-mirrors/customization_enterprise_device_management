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

#ifndef SERVICES_EDM_INCLUDE_UTILS_NEARLINK_CONFIG_UTILS_H
#define SERVICES_EDM_INCLUDE_UTILS_NEARLINK_CONFIG_UTILS_H

#include <fstream>
#include <string>

#include "cJSON.h"

#include "cjson_check.h"

namespace OHOS {
namespace EDM {
class NearlinkConfigUtils {
public:
    NearlinkConfigUtils();
    ~NearlinkConfigUtils();
    bool UpdateProtocol(const std::string &userId, const std::string &protocol, bool isAdd);
    bool RemoveUserIdItem(const std::string &userId);
    bool AddProtocol(const std::string &protocol, const std::string &userId, cJSON *denyList, cJSON *userItem);
    bool RemoveProtocol(const std::string &protocol, const std::string &userId, cJSON *denyList, cJSON *userItem);
    bool RemoveProtocolDenyList();
    bool QueryProtocols(const std::string &userId, std::vector<int32_t> &protocols);

private:
    cJSON *root_;
    bool LoadConfig();
    bool SaveConfig();
    bool CreateNearlinkConfigDir(const std::string &dir);
    bool CheckProtocolDenyListExists();
    bool IsProtocolExist(const std::string &protocol, cJSON *userItem);
};
}  // namespace EDM
}  // namespace OHOS
#endif  // SERVICES_EDM_INCLUDE_UTILS_NEARLINK_CONFIG_UTILS_H