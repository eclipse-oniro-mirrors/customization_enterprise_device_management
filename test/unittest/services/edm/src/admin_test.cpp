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

#include <gtest/gtest.h>

#include "byod_admin.h"
#include "device_admin.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "sub_super_device_admin.h"
#include "super_device_admin.h"
#include "virtual_device_admin.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_BUNDLE_NAME = "com.edm.test.demo";
class AdminTest : public testing::Test {};

/**
 * @tc.name: TestGetAdminTypeWithSuperAdmin
 * @tc.desc: Test AdminManager::GetAdminType.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestGetAdminTypeWithSuperAdmin, TestSize.Level1)
{
    AdminInfo adminInfo = {.parentAdminName_ = TEST_BUNDLE_NAME, .adminType_ = AdminType::ENT};
    std::shared_ptr<Admin> admin = std::make_shared<Admin>(adminInfo);
    EXPECT_EQ(admin->GetAdminType(), AdminType::ENT);
    EXPECT_EQ(admin->GetParentAdminName(), TEST_BUNDLE_NAME);
    EXPECT_EQ(admin->IsSuperAdmin(), true);
    EXPECT_EQ(admin->IsDisallowedUninstall(), false);
    EXPECT_EQ(admin->IsEnterpriseAdminKeepAlive(), false);
    EXPECT_EQ(admin->IsAllowedAcrossAccountSetPolicy(), false);
    EXPECT_EQ(admin->HasPermissionToCallServiceCode(EdmInterfaceCode::REMOVE_DEVICE_ADMIN), false);
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_DISABLED_BLUETOOTH, FuncOperateType::SET), false);
    EXPECT_EQ(admin->GetDisableSelfPermission(), EdmPermission::PERMISSION_DENIED);
}

/**
 * @tc.name: TestByodAdmin
 * @tc.desc: Test ByodAdmin.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestByodAdmin, TestSize.Level1)
{
    AdminInfo adminInfo;
    std::shared_ptr<Admin> admin = std::make_shared<ByodAdmin>(adminInfo);
    EXPECT_EQ(admin->GetAdminType(), AdminType::BYOD);
    EXPECT_TRUE(admin->GetParentAdminName().empty());
    EXPECT_EQ(admin->IsSuperAdmin(), false);
    EXPECT_EQ(admin->IsDisallowedUninstall(), true);
    EXPECT_EQ(admin->IsEnterpriseAdminKeepAlive(), false);
    EXPECT_EQ(admin->IsAllowedAcrossAccountSetPolicy(), false);
    EXPECT_EQ(admin->HasPermissionToCallServiceCode(EdmInterfaceCode::REMOVE_DEVICE_ADMIN), true);
    EXPECT_EQ(admin->HasPermissionToCallServiceCode(EdmInterfaceCode::SUBSCRIBE_MANAGED_EVENT), false);
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_DISABLED_BLUETOOTH, FuncOperateType::SET), true);
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_ADD_OS_ACCOUNT, FuncOperateType::SET), false);
    EXPECT_EQ(admin->GetDisableSelfPermission(), EdmPermission::PERMISSION_GET_ADMINPROVISION_INFO);
}

/**
 * @tc.name: TestDeviceAdmin
 * @tc.desc: Test DeviceAdmin.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestDeviceAdmin, TestSize.Level1)
{
    AdminInfo adminInfo;
    std::shared_ptr<Admin> admin = std::make_shared<DeviceAdmin>(adminInfo);
    EXPECT_EQ(admin->GetAdminType(), AdminType::NORMAL);
    EXPECT_TRUE(admin->GetParentAdminName().empty());
    EXPECT_EQ(admin->IsSuperAdmin(), false);
    EXPECT_EQ(admin->IsDisallowedUninstall(), false);
    EXPECT_EQ(admin->IsEnterpriseAdminKeepAlive(), true);
    EXPECT_EQ(admin->IsAllowedAcrossAccountSetPolicy(), true);
    EXPECT_EQ(admin->HasPermissionToCallServiceCode(EdmInterfaceCode::REMOVE_DEVICE_ADMIN), true);
    EXPECT_EQ(admin->HasPermissionToCallServiceCode(EdmInterfaceCode::SET_DELEGATED_POLICIES), false);
#ifdef FEATURE_PC_ONLY
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_DISABLED_BLUETOOTH, FuncOperateType::SET), true);
    EXPECT_EQ(admin->GetDisableSelfPermission(), EdmPermission::PERMISSION_ENTERPRISE_DEACTIVATE_DEVICE_ADMIN);
#else
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_DISABLED_BLUETOOTH, FuncOperateType::SET), false);
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_SET_BROWSER_POLICIES, FuncOperateType::GET), true);
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_MANAGED_BROWSER_POLICY, FuncOperateType::GET),
        true);
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_SET_BROWSER_POLICIES, FuncOperateType::SET), false);
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_MANAGED_BROWSER_POLICY, FuncOperateType::SET),
        false);
    EXPECT_EQ(admin->GetDisableSelfPermission(), EdmPermission::PERMISSION_DENIED);
#endif
}

/**
 * @tc.name: TestSubSuperDeviceAdmin
 * @tc.desc: Test SubSuperDeviceAdmin.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestSubSuperDeviceAdmin, TestSize.Level1)
{
    AdminInfo adminInfo = {.parentAdminName_ = TEST_BUNDLE_NAME, .adminType_ = AdminType::ENT};
    std::shared_ptr<Admin> admin = std::make_shared<SubSuperDeviceAdmin>(adminInfo);
    EXPECT_EQ(admin->GetAdminType(), AdminType::SUB_SUPER_ADMIN);
    EXPECT_EQ(admin->GetParentAdminName(), TEST_BUNDLE_NAME);
    EXPECT_EQ(admin->IsSuperAdmin(), false);
    EXPECT_EQ(admin->IsDisallowedUninstall(), false);
    EXPECT_EQ(admin->IsEnterpriseAdminKeepAlive(), true);
    EXPECT_EQ(admin->IsAllowedAcrossAccountSetPolicy(), true);
    EXPECT_EQ(admin->HasPermissionToCallServiceCode(EdmInterfaceCode::SUBSCRIBE_MANAGED_EVENT), true);
    EXPECT_EQ(admin->HasPermissionToCallServiceCode(EdmInterfaceCode::REMOVE_DEVICE_ADMIN), false);
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_DISABLED_BLUETOOTH, FuncOperateType::SET), true);
    EXPECT_EQ(admin->GetDisableSelfPermission(), EdmPermission::PERMISSION_DENIED);
}

/**
 * @tc.name: TestSuperDeviceAdmin
 * @tc.desc: Test AdminManager::GetAdminType.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestSuperDeviceAdmin, TestSize.Level1)
{
    AdminInfo adminInfo;
    std::shared_ptr<Admin> admin = std::make_shared<SuperDeviceAdmin>(adminInfo);
    EXPECT_EQ(admin->GetAdminType(), AdminType::ENT);
    EXPECT_TRUE(admin->GetParentAdminName().empty());
    EXPECT_EQ(admin->IsSuperAdmin(), true);
    EXPECT_EQ(admin->IsDisallowedUninstall(), true);
    EXPECT_EQ(admin->IsEnterpriseAdminKeepAlive(), true);
    EXPECT_EQ(admin->IsAllowedAcrossAccountSetPolicy(), true);
    EXPECT_EQ(admin->HasPermissionToCallServiceCode(EdmInterfaceCode::REMOVE_DEVICE_ADMIN), true);
    EXPECT_EQ(admin->HasPermissionToCallServiceCode(EdmInterfaceCode::IS_BYOD_ADMIN), false);
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_DISABLED_BLUETOOTH, FuncOperateType::SET), true);
    EXPECT_EQ(admin->GetDisableSelfPermission(), EdmPermission::PERMISSION_ENTERPRISE_DEACTIVATE_DEVICE_ADMIN);
}

/**
 * @tc.name: TestVirtualDeviceAdmin
 * @tc.desc: Test VirtualDeviceAdmin.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestVirtualDeviceAdmin, TestSize.Level1)
{
    AdminInfo adminInfo = {.parentAdminName_ = TEST_BUNDLE_NAME,
        .accessiblePolicies_ = {PolicyName::POLICY_DISABLED_BLUETOOTH}, .adminType_ = AdminType::ENT};
    std::shared_ptr<Admin> admin = std::make_shared<VirtualDeviceAdmin>(adminInfo);
    EXPECT_EQ(admin->GetAdminType(), AdminType::VIRTUAL_ADMIN);
    EXPECT_EQ(admin->GetParentAdminName(), TEST_BUNDLE_NAME);
    EXPECT_EQ(admin->IsSuperAdmin(), false);
    EXPECT_EQ(admin->IsDisallowedUninstall(), false);
    EXPECT_EQ(admin->IsEnterpriseAdminKeepAlive(), false);
    EXPECT_EQ(admin->IsAllowedAcrossAccountSetPolicy(), true);
    EXPECT_EQ(admin->HasPermissionToCallServiceCode(EdmInterfaceCode::REMOVE_DEVICE_ADMIN), false);
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_DISABLED_BLUETOOTH, FuncOperateType::SET), true);
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_DISABLE_USB, FuncOperateType::SET), false);
    EXPECT_EQ(admin->GetDisableSelfPermission(), EdmPermission::PERMISSION_DENIED);
}

/**
 * @tc.name: TestVirtualDeviceAdminWithAllowAllPolicy
 * @tc.desc: Test VirtualDeviceAdmin.
 * @tc.type: FUNC
 */
HWTEST_F(AdminTest, TestVirtualDeviceAdminWithAllowAllPolicy, TestSize.Level1)
{
    AdminInfo adminInfo = {.parentAdminName_ = TEST_BUNDLE_NAME,
        .accessiblePolicies_ = {"allow_all"}, .adminType_ = AdminType::ENT};
    std::shared_ptr<Admin> admin = std::make_shared<VirtualDeviceAdmin>(adminInfo);
    EXPECT_EQ(admin->GetAdminType(), AdminType::VIRTUAL_ADMIN);
    EXPECT_EQ(admin->GetParentAdminName(), TEST_BUNDLE_NAME);
    EXPECT_EQ(admin->IsSuperAdmin(), false);
    EXPECT_EQ(admin->IsDisallowedUninstall(), false);
    EXPECT_EQ(admin->IsEnterpriseAdminKeepAlive(), false);
    EXPECT_EQ(admin->IsAllowedAcrossAccountSetPolicy(), true);
    EXPECT_EQ(admin->HasPermissionToCallServiceCode(EdmInterfaceCode::REMOVE_DEVICE_ADMIN), false);
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_DISABLED_BLUETOOTH, FuncOperateType::SET), true);
    EXPECT_EQ(admin->HasPermissionToHandlePolicy(PolicyName::POLICY_DISABLE_USB, FuncOperateType::SET), true);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
