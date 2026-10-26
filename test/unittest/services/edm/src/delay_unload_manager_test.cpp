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

#include <gtest/gtest.h>

#include "admin_manager.h"
#include "delay_unload_manager.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "enterprise_device_mgr_ability.h"
#include "func_code.h"
#include "utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class DelayUnloadManagerTest : public testing::Test {
protected:
    void SetUp() override
    {
        adminMgr_ = AdminManager::GetInstance();
        adminMgr_->ClearAdmins();
    }

    void TearDown() override
    {
        DelayUnloadManager::GetInstance()->CancelDelayUnload();
        Utils::SetEdmServiceDisable();
        adminMgr_->ClearAdmins();
    }

    void AddTestAdmin()
    {
        EntInfo entInfo;
        AdminInfo adminInfo = {.packageName_ = "com.edm.test.delayunload", .className_ = "DelayUnloadTest",
            .entInfo_ = entInfo, .permission_ = {"ohos.permission.EDM_TEST_PERMISSION"},
            .adminType_ = AdminType::NORMAL, .isDebug_ = false};
        std::vector<std::shared_ptr<Admin>> adminVec = {std::make_shared<Admin>(adminInfo)};
        adminMgr_->InsertAdmins(EdmConstants::DEFAULT_USER_ID, adminVec);
    }

    std::shared_ptr<AdminManager> adminMgr_ = nullptr;
};

/**
 * @tc.name: TryStartDelayUnload_AdminExist
 * @tc.desc: Test TryStartDelayUnload does not post unload task when admin exists.
 * @tc.type: FUNC
 */
HWTEST_F(DelayUnloadManagerTest, TryStartDelayUnload_AdminExist_UnloadTaskNotPosted, TestSize.Level1)
{
    AddTestAdmin();
    EXPECT_TRUE(adminMgr_->IsAdminExist());
    DelayUnloadManager::GetInstance()->TryStartDelayUnload();
    EXPECT_FALSE(DelayUnloadManager::GetInstance()->IsPending());
    DelayUnloadManager::GetInstance()->TryStartDelayUnload();
    EXPECT_FALSE(DelayUnloadManager::GetInstance()->IsPending());
}

/**
 * @tc.name: TryStartDelayUnload_NoAdmin
 * @tc.desc: Test TryStartDelayUnload posts unload task when no admin exists.
 * @tc.type: FUNC
 */
HWTEST_F(DelayUnloadManagerTest, TryStartDelayUnload_NoAdmin_UnloadTaskPosted, TestSize.Level1)
{
    EXPECT_FALSE(adminMgr_->IsAdminExist());
    EXPECT_FALSE(DelayUnloadManager::GetInstance()->IsPending());
    DelayUnloadManager::GetInstance()->TryStartDelayUnload();
    EXPECT_TRUE(DelayUnloadManager::GetInstance()->IsPending());
    DelayUnloadManager::GetInstance()->TryStartDelayUnload();
    EXPECT_TRUE(DelayUnloadManager::GetInstance()->IsPending());
}

/**
 * @tc.name: CancelDelayUnload_UnloadTaskPosted
 * @tc.desc: Test CancelDelayUnload removes the posted unload task.
 * @tc.type: FUNC
 */
HWTEST_F(DelayUnloadManagerTest, CancelDelayUnload_UnloadTaskPosted_ThenRemoved, TestSize.Level1)
{
    DelayUnloadManager::GetInstance()->TryStartDelayUnload();
    EXPECT_TRUE(DelayUnloadManager::GetInstance()->IsPending());

    DelayUnloadManager::GetInstance()->CancelDelayUnload();
    EXPECT_FALSE(DelayUnloadManager::GetInstance()->IsPending());

    DelayUnloadManager::GetInstance()->CancelDelayUnload();
    EXPECT_FALSE(DelayUnloadManager::GetInstance()->IsPending());
}

/**
 * @tc.name: OnDelayUnloadTimeout_AdminExist
 * @tc.desc: Test OnDelayUnloadTimeout does not unload when admin exists.
 * @tc.type: FUNC
 */
HWTEST_F(DelayUnloadManagerTest, OnDelayUnloadTimeout_AdminExist_NoUnload, TestSize.Level1)
{
    AddTestAdmin();
    EXPECT_TRUE(adminMgr_->IsAdminExist());
    DelayUnloadManager::GetInstance()->OnDelayUnloadTimeout();
    EXPECT_FALSE(DelayUnloadManager::GetInstance()->IsPending());
    EXPECT_TRUE(adminMgr_->IsAdminExist());
}

/**
 * @tc.name: OnDelayUnloadTimeout_NoAdmin
 * @tc.desc: Test OnDelayUnloadTimeout triggers unload flow when no admin exists.
 * @tc.type: FUNC
 */
HWTEST_F(DelayUnloadManagerTest, OnDelayUnloadTimeout_NoAdmin_UnloadTriggered, TestSize.Level1)
{
    // The unload request is rejected by samgr because the caller process is not edm,
    // which is safe for the test environment.
    DelayUnloadManager::GetInstance()->TryStartDelayUnload();
    EXPECT_TRUE(DelayUnloadManager::GetInstance()->IsPending());
    DelayUnloadManager::GetInstance()->OnDelayUnloadTimeout();
    EXPECT_FALSE(DelayUnloadManager::GetInstance()->IsPending());
    EXPECT_FALSE(adminMgr_->IsAdminExist());
}

/**
 * @tc.name: OnDelayUnloadTimeout_EdmParamEnabled
 * @tc.desc: Test OnDelayUnloadTimeout does not unload when edm is enabled.
 * @tc.type: FUNC
 */
HWTEST_F(DelayUnloadManagerTest, OnDelayUnloadTimeout_EdmParamEnabled_NoUnload, TestSize.Level1)
{
    Utils::SetEdmServiceEnable();
    EXPECT_FALSE(adminMgr_->IsAdminExist());
    DelayUnloadManager::GetInstance()->TryStartDelayUnload();
    EXPECT_TRUE(DelayUnloadManager::GetInstance()->IsPending());
    DelayUnloadManager::GetInstance()->OnDelayUnloadTimeout();
    EXPECT_FALSE(DelayUnloadManager::GetInstance()->IsPending());
    EXPECT_FALSE(adminMgr_->IsAdminExist());
}

/**
 * @tc.name: OnRemoteRequest_SystemAppDenied_TryStartDelayUnload
 * @tc.desc: Test OnRemoteRequest with a service code triggers delay unload when the caller is
 *           not a system app or native process.
 * @tc.type: FUNC
 */
HWTEST_F(DelayUnloadManagerTest, OnRemoteRequest_SystemAppDenied_TryStartDelayUnload, TestSize.Level1)
{
    // Set an invalid token to make sure the caller is not a system app or native process,
    // otherwise the ut runner process may hold a shell token which passes the check.
    uint64_t selfToken = GetSelfTokenID();
    SetSelfTokenID(0);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto stub = EnterpriseDeviceMgrAbility::GetInstance();
    int32_t ret = stub->OnRemoteRequest(EdmInterfaceCode::ADD_DEVICE_ADMIN, data, reply, option);
    SetSelfTokenID(selfToken);
    EXPECT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::SYSTEM_API_DENIED));
    EXPECT_TRUE(DelayUnloadManager::GetInstance()->IsPending());
}

/**
 * @tc.name: OnRemoteRequest_DescriptorMismatch_TryStartDelayUnload
 * @tc.desc: Test OnRemoteRequest with a policy code triggers delay unload when descriptors are
 *           inconsistent.
 * @tc.type: FUNC
 */
HWTEST_F(DelayUnloadManagerTest, OnRemoteRequest_DescriptorMismatch_TryStartDelayUnload, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto stub = EnterpriseDeviceMgrAbility::GetInstance();
    uint32_t code = POLICY_FUNC_CODE(static_cast<int>(FuncOperateType::GET), EdmInterfaceCode::IS_ADMIN_ENABLED);
    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(DelayUnloadManager::GetInstance()->IsPending());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
