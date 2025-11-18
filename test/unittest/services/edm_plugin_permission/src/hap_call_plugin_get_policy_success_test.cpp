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

#define private public
#define protected public
#include "enterprise_device_mgr_ability.h"
#include "plugin_singleton.h"
#undef protected
#undef private

#include "hap_call_plugin_get_policy_success_test.h"

#include <gtest/gtest.h>
#include <gtest/gtest-param-test.h>
#include <memory>
#include <string>
#include <vector>

#include "enterprise_device_mgr_ability_test.h"
#include "utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

const std::string ADMIN_PACKAGE_NAME = "com.test.mdm";
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";
constexpr size_t HAS_USERID = 1;
constexpr int32_t HAS_ADMIN = 0;
constexpr int32_t WITHOUT_ADMIN = 1;

void HapCallPluginGetPolicySuccessTest::SetUp()
{
    edmMgr_->adminMgr_ = AdminManager::GetInstance();
    edmMgr_->policyMgr_ = std::make_shared<PolicyManager>();
    PermissionChecker::instance_ = permissionCheckerMock_;
    EXPECT_CALL(*edmMgr_, GetExternalManagerFactory).WillRepeatedly(DoAll(Return(factoryMock_)));
    EXPECT_CALL(*edmMgr_, GetPermissionChecker).WillRepeatedly(DoAll(Return(permissionCheckerMock_)));
    EXPECT_CALL(*permissionCheckerMock_, GetExternalManagerFactory).WillRepeatedly(DoAll(Return(factoryMock_)));
    EXPECT_CALL(*factoryMock_, CreateBundleManager).WillRepeatedly(DoAll(Return(bundleMgrMock_)));
    EXPECT_CALL(*factoryMock_, CreateAppManager).WillRepeatedly(DoAll(Return(appMgrMock_)));
    EXPECT_CALL(*factoryMock_, CreateOsAccountManager).WillRepeatedly(DoAll(Return(osAccountMgrMock_)));
    EXPECT_CALL(*factoryMock_, CreateAccessTokenManager).WillRepeatedly(DoAll(Return(accessTokenMgr_)));
}

void HapCallPluginGetPolicySuccessTest::TearDown()
{
    edmMgr_->adminMgr_->ClearAdmins();
    edmMgr_->policyMgr_.reset();
    edmMgr_->instance_.clear();
    edmMgr_ = nullptr;
}

INSTANTIATE_TEST_CASE_P(TestWithParam, HapCallPluginGetPolicySuccessTest, testing::ValuesIn(std::vector<TestParam>({
    TestParam(EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE, AllowedAppDistributionTypesPlugin::GetPlugin(),
        AdminType::ENT, true, "", EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY),
    TestParam(EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE, AllowedAppDistributionTypesPlugin::GetPlugin(),
        AdminType::ENT, false, "", EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY),
})));

/**
 * @tc.name: PermissionCheckTest
 * @tc.desc: Test GetDevicePolicy with native called.
 * @tc.type: FUNC
 */
HWTEST_P(HapCallPluginGetPolicySuccessTest, PermissionCheckTest, TestSize.Level1)
{
    auto param = GetParam();
    // 激活Admin
    AdminInfo testAdminInfo;
    Admin testAdmin(testAdminInfo);
    testAdmin.adminInfo_.packageName_ = ADMIN_PACKAGE_NAME;
    testAdmin.adminInfo_.permission_ = {param.GetPermissionName()};
    testAdmin.adminInfo_.adminType_ = param.GetAdminType();
    std::vector<std::shared_ptr<Admin>> adminVec = {std::make_shared<Admin>(testAdmin)};
    edmMgr_->adminMgr_->InsertAdmins(DEFAULT_USER_ID, adminVec);
    // 注册plugin
    PluginManager::GetInstance()->pluginsCode_[param.GetPluginCode()] = param.GetPlugin();
    // Mock外部依赖
    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillRepeatedly(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillRepeatedly(DoAll(SetArgReferee<1>(ADMIN_PACKAGE_NAME),
        Return(ERR_OK)));
    // Mock hap权限
    Utils::SetHapPermission(ADMIN_PACKAGE_NAME, param.GetPermissionName(), param.IsSystemHap());
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, param.GetPluginCode());
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ErrCode res = -1;
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName(ADMIN_PACKAGE_NAME);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(DEFAULT_USER_ID);
    data.WriteString(param.GetPermissionTag());
    if (param.GetAdminType() != AdminType::UNKNOWN) {
        data.WriteInt32(HAS_ADMIN);
        data.WriteParcelable(&elementName);
    } else {
        data.WriteInt32(WITHOUT_ADMIN);
    }
    edmMgr_->OnRemoteRequest(code, data, reply, option);
    res = reply.ReadInt32();
    EXPECT_EQ(res, ERR_OK);
    Utils::ResetHapPermission();
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS