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
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBluetoothProxySendRequestGetPolicy));

    BluetoothInfo bluetoothInfo;
    int32_t ret = proxy_->GetBluetoothInfo(data, bluetoothInfo);
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
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    BluetoothInfo bluetoothInfo;
    int32_t ret = proxy_->GetBluetoothInfo(data, bluetoothInfo);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetBluetoothDisabledSuc
 * @tc.desc: Test SetBluetoothDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestSetBluetoothDisabledSuc, TestSize.Level1)
{
    MessageParcel data;
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(true);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = proxy_->SetBluetoothDisabled(data);
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
    MessageParcel data;
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(true);

    int32_t ret = proxy_->SetBluetoothDisabled(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsBluetoothDisabledSuc
 * @tc.desc: Test IsBluetoothDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestIsBluetoothDisabledSuc, TestSize.Level1)
{
    MessageParcel data;
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));

    bool isDisable = false;
    int32_t ret = proxy_->IsBluetoothDisabled(data, isDisable);
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
    MessageParcel data;
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    bool isDisable = false;
    int32_t ret = proxy_->IsBluetoothDisabled(data, isDisable);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_FALSE(isDisable);
}

/**
 * @tc.name: TestAddAllowedBluetoothDevicesSuc
 * @tc.desc: Test AddAllowedBluetoothDevices func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestAddAllowedBluetoothDevicesSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    std::vector<std::string> deviceIds = { "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    data.WriteStringVector(deviceIds);
    int32_t ret = proxy_->AddOrRemoveBluetoothDevices(data, FuncOperateType::SET,
        EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddDisallowedBluetoothDevicesSuc
 * @tc.desc: Test AddDisallowedBluetoothDevices func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestAddDisallowedBluetoothDevicesSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    std::vector<std::string> deviceIds = { "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    data.WriteStringVector(deviceIds);
    int32_t ret = proxy_->AddOrRemoveBluetoothDevices(data, FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddAllowedBluetoothDevicesFail
 * @tc.desc: Test AddAllowedBluetoothDevices func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestAddAllowedBluetoothDevicesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<std::string> deviceIds;
    MessageParcel data;
    data.WriteParcelable(&admin);
    data.WriteStringVector(deviceIds);
    int32_t ret = proxy_->AddOrRemoveBluetoothDevices(data, FuncOperateType::SET,
        EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddDisallowedBluetoothDevicesFail
 * @tc.desc: Test AddDisallowedBluetoothDevices func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestAddDisallowedBluetoothDevicesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<std::string> deviceIds;
    MessageParcel data;
    data.WriteParcelable(&admin);
    data.WriteStringVector(deviceIds);
    int32_t ret = proxy_->AddOrRemoveBluetoothDevices(data, FuncOperateType::SET,
        EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetAllowedBluetoothDevicesSuc
 * @tc.desc: Test GetAllowedBluetoothDevices func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetAllowedBluetoothDevicesSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeArrayStringSendRequestGetPolicy));
    std::vector<std::string> deviceIds;
    int32_t ret = proxy_->GetAllowedBluetoothDevices(&admin, deviceIds);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(deviceIds.size() == 1);
    ASSERT_EQ(deviceIds[0], RETURN_STRING);
}

/**
 * @tc.name: TestGetAllowedBluetoothDevicesFail
 * @tc.desc: Test GetAllowedBluetoothDevices without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetAllowedBluetoothDevicesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::vector<std::string> deviceIds;
    int32_t ret = proxy_->GetAllowedBluetoothDevices(&admin, deviceIds);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetAllowedBluetoothDevicesWithoutAdminSuc
 * @tc.desc: Test GetAllowedBluetoothDevices func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetAllowedBluetoothDevicesWithoutAdminSuc, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeArrayStringSendRequestGetPolicy));
    std::vector<std::string> deviceIds;
    int32_t ret = proxy_->GetAllowedBluetoothDevices(nullptr, deviceIds);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(deviceIds.size() == 1);
    ASSERT_EQ(deviceIds[0], RETURN_STRING);
}

/**
 * @tc.name: TestGetAllowedBluetoothDevicesSuc
 * @tc.desc: Test GetAllowedBluetoothDevices func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetAllowedBluetoothDevicesSuc001, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeArrayStringSendRequestGetPolicy));

    std::vector<std::string> deviceIds;
    int32_t ret = proxy_->GetBluetoothDevices(data, deviceIds, EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(deviceIds.size() == 1);
    ASSERT_EQ(deviceIds[0], RETURN_STRING);
}

/**
 * @tc.name: TestGetDisallowedBluetoothDevicesSuc
 * @tc.desc: Test GetDisallowedBluetoothDevices func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetDisallowedBluetoothDevicesSuc001, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeArrayStringSendRequestGetPolicy));

    std::vector<std::string> deviceIds;
    int32_t ret = proxy_->GetBluetoothDevices(data, deviceIds, EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(deviceIds.size() == 1);
    ASSERT_EQ(deviceIds[0], RETURN_STRING);
}

/**
 * @tc.name: TestGetAllowedBluetoothDevicesWithoutAdminSuc
 * @tc.desc: Test GetAllowedBluetoothDevices func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetAllowedBluetoothDevicesWithoutAdminSuc001, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeArrayStringSendRequestGetPolicy));
    std::vector<std::string> deviceIds;
    MessageParcel data;
    data.WriteParcelable(nullptr);
    int32_t ret = proxy_->GetBluetoothDevices(data, deviceIds, EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(deviceIds.size() == 1);
    ASSERT_EQ(deviceIds[0], RETURN_STRING);
}

/**
 * @tc.name: TestGetDisallowedBluetoothDevicesWithoutAdminSuc
 * @tc.desc: Test GetDisallowedBluetoothDevices func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetDisallowedBluetoothDevicesWithoutAdminSuc001, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeArrayStringSendRequestGetPolicy));
    std::vector<std::string> deviceIds;
    MessageParcel data;
    data.WriteParcelable(nullptr);
    int32_t ret = proxy_->GetBluetoothDevices(data, deviceIds, EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(deviceIds.size() == 1);
    ASSERT_EQ(deviceIds[0], RETURN_STRING);
}

/**
 * @tc.name: TestGetAllowedBluetoothDevicesFail
 * @tc.desc: Test GetAllowedBluetoothDevices without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetAllowedBluetoothDevicesFail001, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    std::vector<std::string> deviceIds;
    int32_t ret = proxy_->GetBluetoothDevices(data, deviceIds, EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDisallowedBluetoothDevicesFail
 * @tc.desc: Test GetDisallowedBluetoothDevices without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetDisallowedBluetoothDevicesFail001, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    std::vector<std::string> deviceIds;
    int32_t ret = proxy_->GetBluetoothDevices(data, deviceIds, EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetAllowedBluetoothDevicesFail
 * @tc.desc: Test GetAllowedBluetoothDevicesFail func if does not have Admin parameter without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetAllowedBluetoothDevicesFail002, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    const std::u16string descriptor = u"ohos.edm.testdemo";
    data.WriteInterfaceToken(descriptor);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(WITHOUT_ADMIN);
    std::vector<std::string> deviceIds;
    ErrCode ret = proxy_->GetBluetoothDevices(data, deviceIds, EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetDisallowedBluetoothDevicesFail
 * @tc.desc: Test GetDisallowedBluetoothDevicesFail func if does not have Admin parameter without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestGetDisallowedBluetoothDevicesFail002, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    const std::u16string descriptor = u"ohos.edm.testdemo";
    data.WriteInterfaceToken(descriptor);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(WITHOUT_ADMIN);
    std::vector<std::string> deviceIds;
    ErrCode ret = proxy_->GetBluetoothDevices(data, deviceIds, EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveAllowedBluetoothDevicesSuc
 * @tc.desc: Test RemoveAllowedBluetoothDevices func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestRemoveAllowedBluetoothDevicesSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    std::vector<std::string> deviceIds = { "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    data.WriteStringVector(deviceIds);

    int32_t ret = proxy_->AddOrRemoveBluetoothDevices(data, FuncOperateType::REMOVE,
        EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveDisallowedBluetoothDevicesSuc
 * @tc.desc: Test RemoveDisallowedBluetoothDevices func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestRemoveDisallowedBluetoothDevicesSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    std::vector<std::string> deviceIds = { "00:1A:2B:3C:4D:5E", "AA:BB:CC:DD:EE:FF" };
    data.WriteStringVector(deviceIds);

    int32_t ret = proxy_->AddOrRemoveBluetoothDevices(data, FuncOperateType::REMOVE,
        EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveAllowedBluetoothDevicesFail
 * @tc.desc: Test RemoveAllowedBluetoothDevices without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestRemoveAllowedBluetoothDevicesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    std::vector<std::string> deviceIds;
    data.WriteStringVector(deviceIds);

    int32_t ret = proxy_->AddOrRemoveBluetoothDevices(data, FuncOperateType::REMOVE,
        EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveDisallowedBluetoothDevicesFail
 * @tc.desc: Test RemoveDisallowedBluetoothDevices without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestRemoveDisallowedBluetoothDevicesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    std::vector<std::string> deviceIds;
    data.WriteStringVector(deviceIds);

    int32_t ret = proxy_->AddOrRemoveBluetoothDevices(data, FuncOperateType::REMOVE,
        EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestTurnOnBluetoothSuc
 * @tc.desc: Test TurnOnBluetoothSuc func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestTurnOnBluetoothSuc, TestSize.Level1)
{
    MessageParcel data;
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(true);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = proxy_->TurnOnOrOffBluetooth(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
* @tc.name: TestTurnOnBluetoothFail
* @tc.desc: Test TurnOnBluetoothFail func without enable edm service.
* @tc.type: FUNC
*/
HWTEST_F(BluetoothManagerProxyTest, TestTurnOnBluetoothFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(true);

    int32_t ret = proxy_->TurnOnOrOffBluetooth(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
* @tc.name: TestTurnOffBluetoothSuc
* @tc.desc: Test TurnOffBluetoothSuc func.
* @tc.type: FUNC
*/
HWTEST_F(BluetoothManagerProxyTest, TestTurnOffBluetoothSuc, TestSize.Level1)
{
    MessageParcel data;
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(false);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = proxy_->TurnOnOrOffBluetooth(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
* @tc.name: TestTurnOffBluetoothFail
* @tc.desc: Test TurnOffBluetoothFail func without enable edm service.
* @tc.type: FUNC
*/
HWTEST_F(BluetoothManagerProxyTest, TestTurnOffBluetoothFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(false);

    int32_t ret = proxy_->TurnOnOrOffBluetooth(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddOrRemoveDisallowedBluetoothProtocolsFail
 * @tc.desc: Test AddOrRemoveDisallowedBluetoothProtocols without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestAddOrRemoveDisallowedBluetoothProtocolsFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    std::vector<int32_t> protocols;
    data.WriteParcelable(&admin);
    data.WriteInt32Vector(protocols);

    ErrCode ret = proxy_->AddOrRemoveDisallowedBluetoothProtocols(data, true);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddOrRemoveDisallowedBluetoothProtocolsSuc
 * @tc.desc: Test AddOrRemoveDisallowedBluetoothProtocols success func.
 * @tc.type: FUNC
 */
HWTEST_F(BluetoothManagerProxyTest, TestAddOrRemoveDisallowedBluetoothProtocolsSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    std::vector<int32_t> protocols;
    data.WriteParcelable(&admin);
    data.WriteInt32Vector(protocols);

    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    ErrCode ret = proxy_->AddOrRemoveDisallowedBluetoothProtocols(data, true);
    ASSERT_TRUE(ret == ERR_OK);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
