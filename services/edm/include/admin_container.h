/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_ADMIN_CONTAINER_H
#define SERVICES_EDM_INCLUDE_ADMIN_CONTAINER_H
 
#include <map>
#include <memory>
#include <shared_mutex>
#include <unordered_map>
#include "admin.h"
 

namespace OHOS {
namespace EDM {
#define PACKAGE_NAME 1
#define CLASS_NAME (1 << 1)
#define ENTI_NFO (1 << 2)
#define PERMISSION (1 << 3)
#define MANAGED_EVENTS (1 << 4)
#define PARENT_ADMIN_NAME (1 << 5)
#define ACCESSIBLE_POLICIES (1 << 6)
#define ADMIN_TYPE (1 << 7)
#define IS_DEBUG (1 << 8)
#define RUNNING_MODE (1 << 9)

/**
 * This class provides thread-safe access to admin data, with all public methods
 * implementing synchronization control through internal locking mechanisms.
 * It is suitable for admin information management scenarios in multi-threaded environments.
 */
class AdminContainer {
public:
    AdminContainer();

    ~AdminContainer();

    static std::shared_ptr<AdminContainer> GetInstance();

    void SetAdminByUserId(int32_t userId, const AdminInfo &adminItem);

    bool DeleteAdmin(const std::string &packageName, int32_t userId);

    /**
     * Get a thread-safe independent copy of the admin object for the specified user ID.
     */
    bool GetAdminCopyByUserId(int32_t userId, std::vector<std::shared_ptr<Admin>> &admins);

    /**
     * Get a thread-safe independent copy of the admin object for the specified event.
     */
    void GetAdminCopyBySubscribeEvent(ManagedEvent event,
        std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> &subscribeAdmins);

    bool HasAdmin(int32_t userId);

    bool IsAdminExist();

    void UpdateAdmin(int32_t userId, const std::string &packageName, uint32_t updateCode, const AdminInfo &adminInfo);

    void UpdateParentAdminName(int32_t userId, const std::string &parentAdminName, const std::string &updateName);

    void InitAdmins(std::unordered_map<int32_t, std::vector<AdminInfo>> admins);

    void ClearAdmins();

    void InsertAdmins(int32_t userId, std::vector<std::shared_ptr<Admin>> admins);

    void Dump();

    bool IsExistTargetAdmin(bool isDebug);

    int32_t GetSuperDeviceAdminAndDeviceAdminCount();

    std::shared_ptr<Admin> CreateAdmin(const AdminInfo &adminInfo);

private:
    bool GetAdminByUserId(int32_t userId, std::vector<std::shared_ptr<Admin>> &userAdmin);

    std::unordered_map<int32_t, std::vector<std::shared_ptr<Admin>>> admins_;
    std::shared_mutex adminMutex_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_ADMIN_CONTAINER_H