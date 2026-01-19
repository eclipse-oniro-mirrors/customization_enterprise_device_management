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

#include "native_call_plugin_test.h"

#include <gtest/gtest.h>
#include <gtest/gtest-param-test.h>
#include <string>
#include <vector>

#include "allowed_bluetooth_devices_plugin.h"
#include "disable_usb_plugin.h"
#include "disallowed_bluetooth_devices_plugin.h"
#include "enterprise_device_mgr_ability_test.h"
#include "password_policy_plugin.h"
#include "utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

const std::string ADMIN_PACKAGE_NAME = "com.test.mdm";

void NativeCallPluginTest::SetUp()
{
    edmMgr_->adminMgr_ = AdminManager::GetInstance();
    edmMgr_->policyMgr_ = PolicyManager::GetInstance();
    PermissionChecker::instance_ = permissionCheckerMock_;
    EXPECT_CALL(*edmMgr_, GetExternalManagerFactory).WillRepeatedly(DoAll(Return(factoryMock_)));
    EXPECT_CALL(*edmMgr_, GetPermissionChecker).WillRepeatedly(DoAll(Return(permissionCheckerMock_)));
    EXPECT_CALL(*permissionCheckerMock_, GetExternalManagerFactory).WillRepeatedly(DoAll(Return(factoryMock_)));
    EXPECT_CALL(*factoryMock_, CreateBundleManager).WillRepeatedly(DoAll(Return(bundleMgrMock_)));
    EXPECT_CALL(*factoryMock_, CreateAppManager).WillRepeatedly(DoAll(Return(appMgrMock_)));
    EXPECT_CALL(*factoryMock_, CreateOsAccountManager).WillRepeatedly(DoAll(Return(osAccountMgrMock_)));
    EXPECT_CALL(*factoryMock_, CreateAccessTokenManager).WillRepeatedly(DoAll(Return(accessTokenMgr_)));
}

void NativeCallPluginTest::TearDown()
{
    edmMgr_->adminMgr_->ClearAdmins();
    edmMgr_->policyMgr_.reset();
    edmMgr_->instance_.clear();
    edmMgr_ = nullptr;
}

INSTANTIATE_TEST_CASE_P(TestWithParam, NativeCallPluginTest, testing::ValuesIn(std::vector<TestParam>({
    TestParam(EdmInterfaceCode::DISABLE_USB, DisableUsbPlugin::GetPlugin(), "", "usb_service",
        EdmConstants::USB_SERVICE_UID),
    TestParam(EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES, AllowedBluetoothDevicesPlugin::GetPlugin(), "",
        "bluetooth_service", EdmConstants::BLUETOOTH_SERVICE_UID),
    TestParam(EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES, DisallowedBluetoothDevicesPlugin::GetPlugin(), "",
        "bluetooth_service", EdmConstants::BLUETOOTH_SERVICE_UID),
    TestParam(EdmInterfaceCode::PASSWORD_POLICY, PasswordPolicyPlugin::GetPlugin(), "", "useriam",
        EdmConstants::USERIAM_SERVICE_UID)
})));

/**
 * @tc.name: PermissionCheckTest
 * @tc.desc: Test GetDevicePolicy with native called.
 * @tc.type: FUNC
 */
HWTEST_P(NativeCallPluginTest, PermissionCheckTest, TestSize.Level1)
{
    auto param = GetParam();
    // 注册plugin
    PluginManager::GetInstance()->pluginsCode_[param.GetPluginCode()] = param.GetPlugin();
    // Mock外部依赖
    std::vector<int32_t> ids = {DEFAULT_USER_ID};
    EXPECT_CALL(*osAccountMgrMock_, IsOsAccountExists).WillRepeatedly(DoAll(SetArgReferee<1>(true), Return(ERR_OK)));
    EXPECT_CALL(*osAccountMgrMock_, QueryActiveOsAccountIds).WillRepeatedly(DoAll(SetArgReferee<0>(ids),
        Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock_, GetNameForUid).WillRepeatedly(DoAll(SetArgReferee<1>(ADMIN_PACKAGE_NAME),
        Return(ERR_OK)));
    // Mock Native进程
    Utils::SetNativePermission(param.GetProcess(), param.GetUid());
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, param.GetPluginCode());
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(param.GetPermissionTag());
    data.WriteInt32(1); // admin 为 nullptr
    ErrCode res = edmMgr_->GetDevicePolicy(code, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(res, ERR_OK);
    Utils::ResetNativePermission();
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS