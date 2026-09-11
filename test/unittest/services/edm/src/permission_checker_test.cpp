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

#include "permission_checker_test.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "admin_container.h"
#include "admin_manager.h"
#include "edm_constants.h"
#include "enable_source.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

void PermissionCheckerTest::SetUp()
{
    appMgrMock_ = std::make_shared<EdmAppManagerImplMock>();
    bundleMgrMock_ = std::make_shared<EdmBundleManagerImplMock>();
    osAccountMgrMock_ = std::make_shared<EdmOsAccountManagerImplMock>();
    accessTokenMgrMock_ = std::make_shared<EdmAccessTokenManagerImplMock>();
    factoryMock_ = std::make_shared<ExternalManagerFactoryMock>();

    permissionChecker_ = std::make_shared<PermissionCheckerMock>();

    EXPECT_CALL(*permissionChecker_, GetExternalManagerFactory).WillRepeatedly(DoAll(Return(factoryMock_)));
    EXPECT_CALL(*factoryMock_, CreateBundleManager).WillRepeatedly(DoAll(Return(bundleMgrMock_)));
    EXPECT_CALL(*factoryMock_, CreateAppManager).WillRepeatedly(DoAll(Return(appMgrMock_)));
    EXPECT_CALL(*factoryMock_, CreateOsAccountManager).WillRepeatedly(DoAll(Return(osAccountMgrMock_)));
    EXPECT_CALL(*factoryMock_, CreateAccessTokenManager).WillRepeatedly(DoAll(Return(accessTokenMgrMock_)));
}

void PermissionCheckerTest::TearDown() {}

/**
 * @tc.name: TestIsDebugTure
 * @tc.desc: Test PermissionChecker IsDebug func.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionCheckerTest, TestIsDebugTrue, TestSize.Level1)
{
    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(true)));
    bool ret = permissionChecker_->CheckIsDebug();
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestIsDebugFalse
 * @tc.desc: Test PermissionChecker IsDebug func.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionCheckerTest, TestIsDebugFalse, TestSize.Level1)
{
    EXPECT_CALL(*accessTokenMgrMock_, IsDebug).WillOnce(DoAll(Return(false)));
    bool ret = permissionChecker_->CheckIsDebug();
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestIsSystemAppOrNativeTrue
 * @tc.desc: Test PermissionChecker IsSystemAppOrNative func.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionCheckerTest, TestIsSystemAppOrNativeTrue, TestSize.Level1)
{
    EXPECT_CALL(*accessTokenMgrMock_, IsSystemAppOrNative).WillOnce(DoAll(Return(true)));
    bool ret = permissionChecker_->CheckIsSystemAppOrNative();
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestIsSystemAppOrNativeFalse
 * @tc.desc: Test PermissionChecker IsSystemAppOrNative func.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionCheckerTest, TestIsSystemAppOrNativeFalse, TestSize.Level1)
{
    EXPECT_CALL(*accessTokenMgrMock_, IsSystemAppOrNative).WillOnce(DoAll(Return(false)));
    bool ret = permissionChecker_->CheckIsSystemAppOrNative();
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestVerifyCallingPermissionTrue
 * @tc.desc: Test PermissionChecker VerifyCallingPermission func.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionCheckerTest, TestVerifyCallingPermissionTrue, TestSize.Level1)
{
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(true)));
    bool ret = permissionChecker_->VerifyCallingPermission(tokenId, "per");
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestVerifyCallingPermissionFalse
 * @tc.desc: Test PermissionChecker VerifyCallingPermission func.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionCheckerTest, TestVerifyCallingPermissionFalse, TestSize.Level1)
{
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission).WillOnce(DoAll(Return(false)));
    bool ret = permissionChecker_->VerifyCallingPermission(tokenId, "per");
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestGetAdminGrantedPermission
 * @tc.desc: Test PermissionChecker GetAdminGrantedPermission func.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionCheckerTest, TestGetAdminGrantedPermission, TestSize.Level1)
{
    std::vector<std::string> permissions = {EdmPermission::PERMISSION_ENTERPRISE_OPERATE_DEVICE, "test"};
    std::vector<std::string> permissionList;
    permissionChecker_->GetAdminGrantedPermission(permissions, permissionList);
    EXPECT_EQ(permissionList.size(), 1);
}

/**
 * @tc.name: TestVCheckIsSystemApp
 * @tc.desc: Test PermissionChecker CheckIsSystemApp func.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionCheckerTest, TestVCheckIsSystemApp, TestSize.Level1)
{
    EXPECT_CALL(*accessTokenMgrMock_, IsSystemAppCall)
        .Times(2)
        .WillOnce(DoAll(Return(false)))
        .WillOnce(DoAll(Return(true)));
    EXPECT_FALSE(permissionChecker_->CheckIsSystemApp());
    EXPECT_TRUE(permissionChecker_->CheckIsSystemApp());
}

#ifndef FEATURE_PC_ONLY
/**
 * @tc.name: TestCheckSystemTimerPermission_AdminInactive
 * @tc.desc: Test CheckSystemTimerPermission returns ADMIN_INACTIVE when the bundle is not activated.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionCheckerTest, TestCheckSystemTimerPermission_AdminInactive, TestSize.Level1)
{
    ErrCode ret = permissionChecker_->CheckSystemTimerPermission("com.not.activated", 100);
    ASSERT_EQ(ret, EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestCheckSystemTimerPermission_ByodDenied
 * @tc.desc: Test CheckSystemTimerPermission denies a BYOD admin.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionCheckerTest, TestCheckSystemTimerPermission_ByodDenied, TestSize.Level1)
{
    auto adminMgr = AdminManager::GetInstance();
    adminMgr->Init();
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "byod admin";
    AdminInfo adminInfo = {.packageName_ = "com.edm.byod", .className_ = "ByodAdmin",
        .entInfo_ = entInfo, .adminType_ = AdminType::BYOD, .isDebug_ = false};
    ASSERT_EQ(adminMgr->SetAdminValue(EdmConstants::DEFAULT_USER_ID, adminInfo), ERR_OK);

    ErrCode ret = permissionChecker_->CheckSystemTimerPermission("com.edm.byod", EdmConstants::DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED);

    adminMgr->DeleteAdmin("com.edm.byod", EdmConstants::DEFAULT_USER_ID, AdminType::BYOD);
}

/**
 * @tc.name: TestCheckSystemTimerPermission_CheckCallingUidFail
 * @tc.desc: Test CheckSystemTimerPermission returns PERMISSION_DENIED when CheckCallingUid fails.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionCheckerTest, TestCheckSystemTimerPermission_CheckCallingUidFail, TestSize.Level1)
{
    auto adminMgr = AdminManager::GetInstance();
    adminMgr->Init();
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "normal admin";
    AdminInfo adminInfo = {.packageName_ = "com.edm.timer", .className_ = "TimerAdmin",
        .entInfo_ = entInfo, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    ASSERT_EQ(adminMgr->SetAdminValue(EdmConstants::DEFAULT_USER_ID, adminInfo), ERR_OK);

    EXPECT_CALL(*bundleMgrMock_, GetNameForUid)
        .WillOnce(DoAll(SetArgReferee<1>(std::string("other.bundle")), Return(ERR_OK)));
    ErrCode ret = permissionChecker_->CheckSystemTimerPermission("com.edm.timer", EdmConstants::DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PERMISSION_DENIED);

    adminMgr->DeleteAdmin("com.edm.timer", EdmConstants::DEFAULT_USER_ID, AdminType::NORMAL);
}

/**
 * @tc.name: TestCheckSystemTimerPermission_PermissionDenied
 * @tc.desc: Test CheckSystemTimerPermission returns ADMIN_EDM_PERMISSION_DENIED when
 *           VerifyCallingPermission fails.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionCheckerTest, TestCheckSystemTimerPermission_PermissionDenied, TestSize.Level1)
{
    auto adminMgr = AdminManager::GetInstance();
    adminMgr->Init();
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "normal admin";
    AdminInfo adminInfo = {.packageName_ = "com.edm.timer2", .className_ = "TimerAdmin",
        .entInfo_ = entInfo, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    ASSERT_EQ(adminMgr->SetAdminValue(EdmConstants::DEFAULT_USER_ID, adminInfo), ERR_OK);

    EXPECT_CALL(*bundleMgrMock_, GetNameForUid)
        .WillOnce(DoAll(SetArgReferee<1>(std::string("com.edm.timer2")), Return(ERR_OK)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission)
        .WillOnce(DoAll(Return(false)));
    ErrCode ret = permissionChecker_->CheckSystemTimerPermission("com.edm.timer2", EdmConstants::DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::ADMIN_EDM_PERMISSION_DENIED);

    adminMgr->DeleteAdmin("com.edm.timer2", EdmConstants::DEFAULT_USER_ID, AdminType::NORMAL);
}

/**
 * @tc.name: TestCheckSystemTimerPermission_Success
 * @tc.desc: Test CheckSystemTimerPermission returns ERR_OK when all checks pass.
 * @tc.type: FUNC
 */
HWTEST_F(PermissionCheckerTest, TestCheckSystemTimerPermission_Success, TestSize.Level1)
{
    auto adminMgr = AdminManager::GetInstance();
    adminMgr->Init();
    EntInfo entInfo;
    entInfo.enterpriseName = "company";
    entInfo.description = "normal admin";
    AdminInfo adminInfo = {.packageName_ = "com.edm.timer3", .className_ = "TimerAdmin",
        .entInfo_ = entInfo, .adminType_ = AdminType::NORMAL, .isDebug_ = false};
    ASSERT_EQ(adminMgr->SetAdminValue(EdmConstants::DEFAULT_USER_ID, adminInfo), ERR_OK);

    EXPECT_CALL(*bundleMgrMock_, GetNameForUid)
        .WillOnce(DoAll(SetArgReferee<1>(std::string("com.edm.timer3")), Return(ERR_OK)));
    EXPECT_CALL(*accessTokenMgrMock_, VerifyCallingPermission)
        .WillOnce(DoAll(Return(true)));
    ErrCode ret = permissionChecker_->CheckSystemTimerPermission("com.edm.timer3", EdmConstants::DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    adminMgr->DeleteAdmin("com.edm.timer3", EdmConstants::DEFAULT_USER_ID, AdminType::NORMAL);
}
#endif
} // namespace TEST
} // namespace EDM
} // namespace OHOS
