/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <string>
#include <system_ability_definition.h>
#include <vector>

#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "bluetooth_manager_proxy.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
class BluetoothManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<BluetoothManagerProxy> proxy_ = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void BluetoothManagerProxyTest::SetUp()
{
    proxy_ = BluetoothManagerProxy::GetBluetoothManagerProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void BluetoothManagerProxyTest::TearDown()
{
    proxy_.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void BluetoothManagerProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestGetBluetoothInfoSuc
 * @tc.desc: Test GetBluetoothInfo success func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetBluetoothInfoSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBluetoothProxySendRequestGetPolicy));
    BluetoothInfo bluetoothInfo;
    int32_t ret = proxy_->GetBluetoothInfo(admin, bluetoothInfo);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(bluetoothInfo.name == RETURN_STRING);
    ASSERT_TRUE(bluetoothInfo.state == 1);
    ASSERT_TRUE(bluetoothInfo.connectionState == 1);
}

/**
 * @tc.name: TestGetBluetoothInfoFail
 * @tc.desc: Test GetBluetoothInfo without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetBluetoothInfoFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    BluetoothInfo bluetoothInfo;
    int32_t ret = proxy_->GetBluetoothInfo(admin, bluetoothInfo);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetBluetoothDisabledSuc
 * @tc.desc: Test SetBluetoothDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestSetBluetoothDisabledSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = proxy_->SetBluetoothDisabled(admin, true);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetBluetoothDisabledFail
 * @tc.desc: Test SetBluetoothDisabled func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestSetBluetoothDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);

    int32_t ret = proxy_->SetBluetoothDisabled(admin, true);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsBluetoothDisabledSuc
 * @tc.desc: Test IsBluetoothDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestIsBluetoothDisabledSuc, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));

    bool isDisable = false;
    int32_t ret = proxy_->IsBluetoothDisabled(&admin, isDisable);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(isDisable);
}

/**
 * @tc.name: TestIsBluetoothDisabledFail
 * @tc.desc: Test IsBluetoothDisabled func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestIsBluetoothDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);

    bool isDisable = false;
    int32_t ret = proxy_->IsBluetoothDisabled(&admin, isDisable);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_FALSE(isDisable);
}

/**
 * @tc.name: TestSetBluetoothWhitelistSuc
 * @tc.desc: Test SetBluetoothWhitelist func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestSetBluetoothWhitelistSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    std::vector<std::string> whitelist = { "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    int32_t ret = proxy_->SetBluetoothWhitelist(admin, whitelist);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetBluetoothWhitelistFail
 * @tc.desc: Test SetBluetoothWhitelist without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestSetBluetoothWhitelistFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<std::string> whitelist;
    int32_t ret = proxy_->SetBluetoothWhitelist(admin, whitelist);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetBluetoothWhitelistSuc
 * @tc.desc: Test GetBluetoothWhitelist func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetBluetoothWhitelistSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBluetoothProxySendRequestGetPolicy));
    std::vector<std::string> whitelist;
    int32_t ret = proxy_->GetBluetoothWhitelist(admin, whitelist);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetBluetoothWhitelistFail
 * @tc.desc: Test GetBluetoothWhitelist without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetBluetoothWhitelistFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<std::string> whitelist;
    int32_t ret = proxy_->GetBluetoothWhitelist(admin, whitelist);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetBluetoothWhitelistWithoutAdminSuc
 * @tc.desc: Test GetBluetoothWhitelist func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetBluetoothWhitelistWithoutAdminSuc, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    std::vector<std::string> whitelist;
    int32_t ret = proxy_->GetBluetoothWhitelist(whitelist);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveBluetoothWhitelistSuc
 * @tc.desc: Test RemoveBluetoothWhitelist func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestRemoveBluetoothWhitelistSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    std::vector<std::string> whitelist = { "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    int32_t ret = proxy_->RemoveBluetoothWhitelist(admin, whitelist);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveBluetoothWhitelistFail
 * @tc.desc: Test RemoveBluetoothWhitelist without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestRemoveBluetoothWhitelistFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<std::string> whitelist;
    int32_t ret = proxy_->RemoveBluetoothWhitelist(admin, whitelist);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
