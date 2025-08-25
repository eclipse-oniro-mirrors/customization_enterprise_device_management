/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "message_parcel_utils.h"
#include "utils.h"
#include "wifi_id.h"
#include "wifi_manager_proxy.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
class WifiManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<WifiManagerProxy> wifiManagerProxy = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void WifiManagerProxyTest::SetUp()
{
    wifiManagerProxy = WifiManagerProxy::GetWifiManagerProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void WifiManagerProxyTest::TearDown()
{
    wifiManagerProxy.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void WifiManagerProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestIsWifiActiveSuc
 * @tc.desc: Test IsWifiActive func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestIsWifiActiveSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool isActive = false;
    int32_t ret = wifiManagerProxy->IsWifiActive(data, isActive);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(isActive);
}

/**
 * @tc.name: TestIsWifiActiveFail
 * @tc.desc: Test IsWifiActive func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestIsWifiActiveFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    bool isActive = false;
    int32_t ret = wifiManagerProxy->IsWifiActive(data, isActive);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_FALSE(isActive);
}

/**
 * @tc.name: TestSetWifiProfileSuc
 * @tc.desc: Test SetWifiProfile success func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestSetWifiProfileSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    Wifi::WifiDeviceConfig config;
    config.wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv6 = { 0x01 };
    WifiPassword pwd;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    MessageParcelUtils::WriteWifiDeviceConfig(config, data, pwd);

    int32_t ret = wifiManagerProxy->SetWifiProfile(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetWifiProfileFail
 * @tc.desc: Test SetWifiProfile func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestSetWifiProfileFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    Wifi::WifiDeviceConfig config;
    config.wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv6 = { 0x01 };
    WifiPassword pwd;
    MessageParcelUtils::WriteWifiDeviceConfig(config, data, pwd);

    int32_t ret = wifiManagerProxy->SetWifiProfile(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetWifiDisabledSuc
 * @tc.desc: Test SetWifiDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestSetWifiDisabledSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(true);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = wifiManagerProxy->SetWifiDisabled(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetWifiDisabledFail
 * @tc.desc: Test SetWifiDisabled func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestSetWifiDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(true);

    int32_t ret = wifiManagerProxy->SetWifiDisabled(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsWifiDisabledSuc
 * @tc.desc: Test IsWifiDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestIsWifiDisabledSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));
    bool isDisable = false;
    int32_t ret = wifiManagerProxy->IsWifiDisabled(data, isDisable);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(isDisable);
}

/**
 * @tc.name: TestIsWifiDisabledFail
 * @tc.desc: Test IsWifiDisabled func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestIsWifiDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    bool isDisable = false;
    int32_t ret = wifiManagerProxy->IsWifiDisabled(data, isDisable);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_FALSE(isDisable);
}

/**
 * @tc.name: TestAddAllowedWifiListSuc
 * @tc.desc: Test AddAllowedWifiList success func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestAddAllowedWifiListSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    WifiId id1;
    id1.SetSsid("wifi_name");
    id1.SetBssid("68:77:24:77:A6:D6");
    data.WriteUint32(1);
    id1.Marshalling(data);

    int32_t ret = wifiManagerProxy->AddOrRemoveWifiList(data, FuncOperateType::SET,
        EdmInterfaceCode::ALLOWED_WIFI_LIST);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddAllowedWifiListWithoutBssidSuc
 * @tc.desc: Test AddAllowedWifiList success func without Bssid.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestAddAllowedWifiListSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    WifiId id1;
    id1.SetSsid("wifi_name");
    data.WriteUint32(1);
    id1.Marshalling(data);

    int32_t ret = wifiManagerProxy->AddOrRemoveWifiList(data, FuncOperateType::SET,
        EdmInterfaceCode::ALLOWED_WIFI_LIST);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddAllowedWifiListFail
 * @tc.desc: Test AddAllowedWifiList without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestAddAllowedWifiListFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    WifiId id1;
    id1.SetSsid("wifi_name");
    id1.SetBssid("68:77:24:77:A6:D6");
    data.WriteUint32(1);
    id1.Marshalling(data);

    int32_t ret = wifiManagerProxy->AddOrRemoveWifiList(data, FuncOperateType::SET,
        EdmInterfaceCode::ALLOWED_WIFI_LIST);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveAllowedWifiListSuc
 * @tc.desc: Test RemoveAllowedWifiList success func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestRemoveAllowedWifiListSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    WifiId id1;
    id1.SetSsid("wifi_name");
    id1.SetBssid("68:77:24:77:A6:D6");
    data.WriteUint32(1);
    id1.Marshalling(data);

    int32_t ret = wifiManagerProxy->AddOrRemoveWifiList(data, FuncOperateType::REMOVE,
        EdmInterfaceCode::ALLOWED_WIFI_LIST);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveAllowedWifiListWithoutBssidSuc
 * @tc.desc: Test RemoveAllowedWifiList success without Bssid func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestRemoveAllowedWifiListSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    WifiId id1;
    id1.SetSsid("wifi_name");
    data.WriteUint32(1);
    id1.Marshalling(data);

    int32_t ret = wifiManagerProxy->AddOrRemoveWifiList(data, FuncOperateType::REMOVE,
        EdmInterfaceCode::ALLOWED_WIFI_LIST);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveAllowedWifiListFail
 * @tc.desc: Test RemoveAllowedWifiList without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestRemoveAllowedWifiListFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    WifiId id1;
    id1.SetSsid("wifi_name");
    id1.SetBssid("68:77:24:77:A6:D6");
    data.WriteUint32(1);
    id1.Marshalling(data);

    int32_t ret = wifiManagerProxy->AddOrRemoveWifiList(data, FuncOperateType::REMOVE,
        EdmInterfaceCode::ALLOWED_WIFI_LIST);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetAllowedWifiListSuc
 * @tc.desc: Test GetAllowedWifiList func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestGetAllowedWifiListSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(),
        &EnterpriseDeviceMgrStubMock::InvokeWifiListSendRequestGetPolicy));

    std::vector<WifiId> wifiIds;
    int32_t ret = wifiManagerProxy->GetWifiList(data, wifiIds, EdmInterfaceCode::ALLOWED_WIFI_LIST);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(wifiIds.size() == 1);
}

/**
 * @tc.name: TestGetAllowedWifiListFail
 * @tc.desc: Test GetAllowedWifiList func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestGetAllowedWifiListFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    std::vector<WifiId> wifiIds;
    int32_t ret = wifiManagerProxy->GetWifiList(data, wifiIds, EdmInterfaceCode::ALLOWED_WIFI_LIST);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_TRUE(wifiIds.empty());
}

/**
 * @tc.name: TestAddDisallowedWifiListSuc
 * @tc.desc: Test AddDisallowedWifiList success func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestAddDisallowedWifiListSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    WifiId id1;
    id1.SetSsid("wifi_name");
    id1.SetBssid("68:77:24:77:A6:D6");
    data.WriteUint32(1);
    id1.Marshalling(data);

    int32_t ret = wifiManagerProxy->AddOrRemoveWifiList(data, FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_WIFI_LIST);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddDisallowedWifiListFail
 * @tc.desc: Test AddDisallowedWifiList without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestAddDisallowedWifiListFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    WifiId id1;
    id1.SetSsid("wifi_name");
    id1.SetBssid("68:77:24:77:A6:D6");
    data.WriteUint32(1);
    id1.Marshalling(data);

    int32_t ret = wifiManagerProxy->AddOrRemoveWifiList(data, FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_WIFI_LIST);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveDisallowedWifiListSuc
 * @tc.desc: Test RemoveDisallowedWifiList success func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestRemoveDisallowedWifiListSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    WifiId id1;
    id1.SetSsid("wifi_name");
    id1.SetBssid("68:77:24:77:A6:D6");
    data.WriteUint32(1);
    id1.Marshalling(data);

    int32_t ret = wifiManagerProxy->AddOrRemoveWifiList(data, FuncOperateType::REMOVE,
        EdmInterfaceCode::DISALLOWED_WIFI_LIST);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveDisallowedWifiListFail
 * @tc.desc: Test RemoveDisallowedWifiList without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestRemoveDisallowedWifiListFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    WifiId id1;
    id1.SetSsid("wifi_name");
    id1.SetBssid("68:77:24:77:A6:D6");
    data.WriteUint32(1);
    id1.Marshalling(data);

    int32_t ret = wifiManagerProxy->AddOrRemoveWifiList(data, FuncOperateType::REMOVE,
        EdmInterfaceCode::DISALLOWED_WIFI_LIST);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDisallowedWifiListSuc
 * @tc.desc: Test GetDisallowedWifiList func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestGetDisallowedWifiListSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(),
        &EnterpriseDeviceMgrStubMock::InvokeWifiListSendRequestGetPolicy));

    std::vector<WifiId> wifiIds;
int32_t ret = wifiManagerProxy->GetWifiList(data, wifiIds, EdmInterfaceCode::DISALLOWED_WIFI_LIST);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(wifiIds.size() == 1);
}

/**
 * @tc.name: TestGetDisallowedWifiListFail
 * @tc.desc: Test GetDisallowedWifiList func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestGetDisallowedWifiListFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    std::vector<WifiId> wifiIds;
    int32_t ret = wifiManagerProxy->GetWifiList(data, wifiIds, EdmInterfaceCode::DISALLOWED_WIFI_LIST);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_TRUE(wifiIds.empty());
}

/**
 * @tc.name: TestForceTurnOnWifiSuc
 * @tc.desc: Test TurnOnWifi func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestForceTurnOnWifiSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(true);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeWifiListSendRequestGetPolicy));

    int32_t ret = wifiManagerProxy->TurnOnWifi(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestForceTurnOnWifiFail
 * @tc.desc: Test TurnOnWifi func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestForceTurnOnWifiFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(true);
    int32_t ret = wifiManagerProxy->TurnOnWifi(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestTurnOnWifiSuc
 * @tc.desc: Test TurnOnWifi func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestTurnOnWifiSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(false);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeWifiListSendRequestGetPolicy));

    int32_t ret = wifiManagerProxy->TurnOnWifi(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestTurnOnWifiFail
 * @tc.desc: Test TurnOnWifi func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestTurnOnWifiFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(false);
    int32_t ret = wifiManagerProxy->TurnOnWifi(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestTurnOffWifiSuc
 * @tc.desc: Test TurnOffWifi func.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestTurnOffWifiSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeWifiListSendRequestGetPolicy));

    int32_t ret = wifiManagerProxy->TurnOffWifi(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestTurnOffWifiFail
 * @tc.desc: Test TurnOffWifi func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(WifiManagerProxyTest, TestTurnOffWifiFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    int32_t ret = wifiManagerProxy->TurnOffWifi(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
