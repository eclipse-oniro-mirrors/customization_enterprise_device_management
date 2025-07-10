 /*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_PERMISSION_MANAGED_STATE_SERIALIZER_H
#define INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_PERMISSION_MANAGED_STATE_SERIALIZER_H

#include <map>

#include "ipolicy_serializer.h"

#include "permission_managed_state_info.h"
namespace OHOS {
namespace EDM {

/*
* Policy data serializer of type int.
*/
class PermissionManagedStateSerializer : public IPolicySerializer<std::map<std::string, PermissionManagedStateInfo>>,
    public DelayedSingleton<PermissionManagedStateSerializer> {
public:

    bool Deserialize(const std::string &policy, std::map<std::string, PermissionManagedStateInfo> &dataObj) override;

    bool Serialize(const std::map<std::string, PermissionManagedStateInfo> &dataObj, std::string &policy) override;

    bool GetPolicy(MessageParcel &data, std::map<std::string, PermissionManagedStateInfo> &result) override;

    bool WritePolicy(MessageParcel &reply, std::map<std::string, PermissionManagedStateInfo> &result) override;

    bool MergePolicy(std::vector<std::map<std::string, PermissionManagedStateInfo>> &data,
        std::map<std::string, PermissionManagedStateInfo> &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_SECURITY_MANAGER_INCLUDE_PERMISSION_MANAGED_STATE_SERIALIZER_H
 