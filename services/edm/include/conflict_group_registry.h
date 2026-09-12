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

#ifndef SERVICES_EDM_INCLUDE_QUERY_POLICY_CONFLICT_GROUP_REGISTRY_H
#define SERVICES_EDM_INCLUDE_QUERY_POLICY_CONFLICT_GROUP_REGISTRY_H

#include <cstdint>
#include <unordered_map>

namespace OHOS {
namespace EDM {

enum class ConflictGroupId {
    NONE = 0,
    GROUP_USB = 1,
    GROUP_BLUETOOTH = 2,
    GROUP_SUDO = 3,
    GROUP_NOTIFICATION = 4,
    GROUP_DISTRIBUTED = 5,
    GROUP_MTP = 6,
    GROUP_WIFI = 7,
    GROUP_PRINTER = 8,
    GROUP_RUNNING_BUNDLES = 9,
    GROUP_FACTORY_RESET = 10,
    GROUP_SUPERHUB = 11,
    GROUP_UPDATE_POLICY = 12,
    END
};

class ConflictGroupRegistry {
public:
    static ConflictGroupRegistry& GetInstance();
    int32_t GetConflictGroupId(uint32_t policyCode) const;

private:
    ConflictGroupRegistry();
    void RegisterConflictGroupUsb();
    void RegisterConflictGroupBluetooth();
    void RegisterConflictGroupSudo();
    void RegisterConflictGroupNotification();
    void RegisterConflictGroupDistribute();
    void RegisterConflictGroupMTP();
    void RegisterConflictGroupWifi();
    void RegisterConflictGroupPrinter();
    void RegisterConflictGroupRunningBundles();
    void RegisterConflictGroupResetFactory();
    void RegisterConflictGroupSuperHub();
    void RegisterConflictGroupUpdatePolicy();
    std::unordered_map<uint32_t, int32_t> policyToGroup_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_QUERY_POLICY_CONFLICT_GROUP_REGISTRY_H
