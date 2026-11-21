/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "array_odd_burn_usb_device_serializer.h"
#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "external_storage_device_info.h"
#include "func_code.h"
#include "mount_policy.h"
#include "odd_burn_usb_device.h"
#include "usb_device_id.h"
#include "usb_interface_type.h"
#include "usb_manager_proxy.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
const int32_t TEST_ACCOUNT_ID = 100;
class UsbManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<UsbManagerProxy> proxy_ = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void UsbManagerProxyTest::SetUp()
{
    proxy_ = UsbManagerProxy::GetUsbManagerProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void UsbManagerProxyTest::TearDown()
{
    if (object_ != nullptr) {
        Mock::VerifyAndClearExpectations(object_.GetRefPtr());
    }
    proxy_.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void UsbManagerProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestSetUsbReadOnlySuc
 * @tc.desc: Test SetUsbReadOnly success func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestSetUsbReadOnlySuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(1);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = proxy_->SetUsbReadOnly(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetUsbReadOnlyFail
 * @tc.desc: Test SetUsbReadOnly without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestSetUsbReadOnlyFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(1);

    int32_t ret = proxy_->SetUsbReadOnly(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestDisableUsbSuc
 * @tc.desc: Test DisableUsb success func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestDisableUsbSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(true);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = proxy_->DisableUsb(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisableUsbFail
 * @tc.desc: Test DisableUsb without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestDisableUsbFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(true);

    int32_t ret = proxy_->DisableUsb(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsUsbDisabledSuc
 * @tc.desc: Test IsUsbDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestIsUsbDisabledSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));

    bool isDisable = false;
    int32_t ret = proxy_->IsUsbDisabled(data, isDisable);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(isDisable);
}

/**
 * @tc.name: TestIsUsbDisabledFail
 * @tc.desc: Test IsUsbDisabled func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestIsUsbDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    bool isDisable = false;
    int32_t ret = proxy_->IsUsbDisabled(data, isDisable);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_FALSE(isDisable);
}

/**
 * @tc.name: TestAddAllowedUsbDevicesSuc
 * @tc.desc: Test AddAllowedUsbDevices success func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestAddAllowedUsbDevicesSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    UsbDeviceId id1;
    id1.SetVendorId(1);
    id1.SetProductId(9);
    data.WriteUint32(1);
    id1.Marshalling(data);

    int32_t ret = proxy_->AddAllowedUsbDevices(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddAllowedUsbDevicesFail
 * @tc.desc: Test AddAllowedUsbDevices without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestAddAllowedUsbDevicesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    UsbDeviceId id1;
    id1.SetVendorId(1);
    id1.SetProductId(9);
    data.WriteUint32(1);
    id1.Marshalling(data);

    int32_t ret = proxy_->AddAllowedUsbDevices(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveAllowedUsbDevicesSuc
 * @tc.desc: Test RemoveAllowedUsbDevices success func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestRemoveAllowedUsbDevicesSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    UsbDeviceId id1;
    id1.SetVendorId(1);
    id1.SetProductId(9);
    data.WriteUint32(1);
    id1.Marshalling(data);

    int32_t ret = proxy_->RemoveAllowedUsbDevices(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveAllowedUsbDevicesFail
 * @tc.desc: Test RemoveAllowedUsbDevices without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestRemoveAllowedUsbDevicesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    UsbDeviceId id1;
    id1.SetVendorId(1);
    id1.SetProductId(9);
    data.WriteUint32(1);
    id1.Marshalling(data);

    int32_t ret = proxy_->RemoveAllowedUsbDevices(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetAllowedUsbDevicesSuc
 * @tc.desc: Test GetAllowedUsbDevices func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestGetAllowedUsbDevicesSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(),
            &EnterpriseDeviceMgrStubMock::InvokeAllowedUsbDevicesSendRequestGetPolicy));

    std::vector<UsbDeviceId> usbDeviceIds;
    int32_t ret = proxy_->GetAllowedUsbDevices(data, usbDeviceIds);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(usbDeviceIds.size() == 1);
}

/**
 * @tc.name: TestGetAllowedUsbDevicesFail
 * @tc.desc: Test GetAllowedUsbDevices func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestGetAllowedUsbDevicesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    std::vector<UsbDeviceId> usbDeviceIds;
    int32_t ret = proxy_->GetAllowedUsbDevices(data, usbDeviceIds);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_TRUE(usbDeviceIds.empty());
}

/**
 * @tc.name: TestSetUsbStorageDeviceAccessPolicySuc
 * @tc.desc: Test SetUsbStorageDeviceAccessPolicy success func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestSetUsbStorageDeviceAccessPolicySuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(2);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = proxy_->SetUsbStorageDeviceAccessPolicy(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetUsbStorageDeviceAccessPolicyFail
 * @tc.desc: Test SetUsbStorageDeviceAccessPolicy without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestSetUsbStorageDeviceAccessPolicyFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(2);

    int32_t ret = proxy_->SetUsbStorageDeviceAccessPolicy(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetUsbStorageDeviceAccessPolicySuc
 * @tc.desc: Test GetUsbStorageDeviceAccessPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestGetUsbStorageDeviceAccessPolicySuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeIntSendRequestGetPolicy));

    int32_t policy = -1;
    int32_t ret = proxy_->GetUsbStorageDeviceAccessPolicy(data, policy);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policy == 0);
}

/**
 * @tc.name: TestGetUsbStorageDeviceAccessPolicyFail
 * @tc.desc: Test GetUsbStorageDeviceAccessPolicy func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestGetUsbStorageDeviceAccessPolicyFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    int32_t policy = 0;
    int32_t ret = proxy_->GetUsbStorageDeviceAccessPolicy(data, policy);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddOrRemoveDisallowedUsbDevicesAddSuc
 * @tc.desc: Test AddOrRemoveDisallowedUsbDevices add success func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestAddOrRemoveDisallowedUsbDevicesAddSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    USB::UsbDeviceType type;
    type.baseClass = 3;
    type.subClass = 1;
    type.protocol = 2;
    type.isDeviceType = false;
    data.WriteUint32(1);
    type.Marshalling(data);

    int32_t ret = proxy_->AddOrRemoveDisallowedUsbDevices(data, true);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddOrRemoveDisallowedUsbDevicesAddFail
 * @tc.desc: Test AddOrRemoveDisallowedUsbDevices for adding without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestAddOrRemoveDisallowedUsbDevicesAddFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    USB::UsbDeviceType type;
    type.baseClass = 3;
    type.subClass = 1;
    type.protocol = 2;
    type.isDeviceType = false;
    data.WriteUint32(1);
    type.Marshalling(data);

    int32_t ret = proxy_->AddOrRemoveDisallowedUsbDevices(data, true);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestAddOrRemoveDisallowedUsbDevicesRemoveSuc
 * @tc.desc: Test AddOrRemoveDisallowedUsbDevices remove success func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestAddOrRemoveDisallowedUsbDevicesRemoveSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    USB::UsbDeviceType type;
    type.baseClass = 3;
    type.subClass = 1;
    type.protocol = 2;
    data.WriteUint32(1);
    type.Marshalling(data);

    int32_t ret = proxy_->AddOrRemoveDisallowedUsbDevices(data, false);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddOrRemoveDisallowedUsbDevicesRemoveFail
 * @tc.desc: Test AddOrRemoveDisallowedUsbDevices for removing without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestAddOrRemoveDisallowedUsbDevicesRemoveFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    USB::UsbDeviceType type;
    type.baseClass = 3;
    type.subClass = 1;
    type.protocol = 2;
    type.isDeviceType = false;
    data.WriteUint32(1);
    type.Marshalling(data);

    int32_t ret = proxy_->AddOrRemoveDisallowedUsbDevices(data, false);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDisallowedUsbDevicesSuc
 * @tc.desc: Test GetDisallowedUsbDevices func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestGetDisallowedUsbDevicesSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(),
            &EnterpriseDeviceMgrStubMock::InvokeDisallowedUsbDevicesSendRequestGetPolicy));

    std::vector<USB::UsbDeviceType> result;
    int32_t ret = proxy_->GetDisallowedUsbDevices(data, result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result.size() == 1);
}

/**
 * @tc.name: TestGetDisallowedUsbDevicesFail
 * @tc.desc: Test GetDisallowedUsbDevices func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestGetDisallowedUsbDevicesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    std::vector<USB::UsbDeviceType> result;
    int32_t ret = proxy_->GetDisallowedUsbDevices(data, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_TRUE(result.empty());
}

/**
 * @tc.name: TestSetExternalStorageInterceptEnableSuc
 * @tc.desc: Test SetExternalStorageInterceptEnable success func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestSetExternalStorageInterceptEnableSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(true);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = proxy_->SetExternalStorageInterceptEnable(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetExternalStorageInterceptEnableFail
 * @tc.desc: Test SetExternalStorageInterceptEnable without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestSetExternalStorageInterceptEnableFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(true);

    int32_t ret = proxy_->SetExternalStorageInterceptEnable(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsExternalStorageInterceptEnableSuc
 * @tc.desc: Test IsExternalStorageInterceptEnable func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestIsExternalStorageInterceptEnableSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));

    bool isEnabled = false;
    int32_t ret = proxy_->IsExternalStorageInterceptEnable(data, isEnabled);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(isEnabled);
}

/**
 * @tc.name: TestIsExternalStorageInterceptEnableFail
 * @tc.desc: Test IsExternalStorageInterceptEnable func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestIsExternalStorageInterceptEnableFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    bool isEnabled = false;
    int32_t ret = proxy_->IsExternalStorageInterceptEnable(data, isEnabled);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_FALSE(isEnabled);
}

/**
 * @tc.name: TestSetUsbInterceptEnableSuc
 * @tc.desc: Test SetUsbInterceptEnable success func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestSetUsbInterceptEnableSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(true);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = proxy_->SetUsbInterceptEnable(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetUsbInterceptEnableFail
 * @tc.desc: Test SetUsbInterceptEnable without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestSetUsbInterceptEnableFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteBool(true);

    int32_t ret = proxy_->SetUsbInterceptEnable(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsUsbInterceptEnableSuc
 * @tc.desc: Test IsUsbInterceptEnable func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestIsUsbInterceptEnableSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));

    bool isEnabled = false;
    int32_t ret = proxy_->IsUsbInterceptEnable(data, isEnabled);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(isEnabled);
}

/**
 * @tc.name: TestIsUsbInterceptEnableFail
 * @tc.desc: Test IsUsbInterceptEnable func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestIsUsbInterceptEnableFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    bool isEnabled = false;
    int32_t ret = proxy_->IsUsbInterceptEnable(data, isEnabled);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_FALSE(isEnabled);
}

/**
 * @tc.name: TestSetUsbDeviceStatesSuc
 * @tc.desc: Test SetUsbDeviceStates success func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestSetUsbDeviceStatesSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    USBDeviceConfigInfo config;
    config.busNum = 1;
    config.devAddress = 2;
    ASSERT_TRUE(config.Marshalling(data));
    data.WriteBool(true);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = proxy_->SetUsbDeviceStates(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetUsbDeviceStatesFail
 * @tc.desc: Test SetUsbDeviceStates without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestSetUsbDeviceStatesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    USBDeviceConfigInfo config;
    config.busNum = 1;
    config.devAddress = 2;
    ASSERT_TRUE(config.Marshalling(data));
    data.WriteBool(true);
    int32_t ret = proxy_->SetUsbDeviceStates(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetUsbDeviceInfosFail
 * @tc.desc: Test GetUsbDeviceInfos without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestGetUsbDeviceInfosFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    std::vector<UsbDeviceInfo> result;
    int32_t ret = proxy_->GetUsbDeviceInfos(data, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_TRUE(result.empty());
}

/**
 * @tc.name: TestSetExternalStorageDeviceMountPolicySuc
 * @tc.desc: Test SetExternalStorageDeviceMountPolicy success func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestSetExternalStorageDeviceMountPolicySuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteString("volume_1");
    data.WriteInt32(static_cast<int32_t>(MountPolicy::MOUNT_READ_ONLY));
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = proxy_->SetExternalStorageDeviceMountPolicy(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetExternalStorageDeviceMountPolicyFail
 * @tc.desc: Test SetExternalStorageDeviceMountPolicy without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestSetExternalStorageDeviceMountPolicyFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteString("volume_1");
    data.WriteInt32(static_cast<int32_t>(MountPolicy::MOUNT_READ_ONLY));

    int32_t ret = proxy_->SetExternalStorageDeviceMountPolicy(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetExternalStorageDeviceInfosSuc
 * @tc.desc: Test GetExternalStorageDeviceInfos func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestGetExternalStorageDeviceInfosSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(),
            &EnterpriseDeviceMgrStubMock::InvokeExternalStorageDeviceInfosSendRequestGetPolicy));

    std::vector<ExternalStorageDeviceInfo> deviceInfos;
    int32_t ret = proxy_->GetExternalStorageDeviceInfos(data, deviceInfos);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(deviceInfos.size() == 1);
    ASSERT_TRUE(deviceInfos[0].devicePath == "/dev/block/sda1");
    ASSERT_TRUE(deviceInfos[0].volumeId == "volume_1");
    ASSERT_TRUE(deviceInfos[0].mountStatus);
    ASSERT_TRUE(deviceInfos[0].vendorId == 1);
    ASSERT_TRUE(deviceInfos[0].productId == 9);
    ASSERT_TRUE(deviceInfos[0].serial == "serial_1");
}

/**
 * @tc.name: TestGetExternalStorageDeviceInfosFail
 * @tc.desc: Test GetExternalStorageDeviceInfos func without enable edm service.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestGetExternalStorageDeviceInfosFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    std::vector<ExternalStorageDeviceInfo> deviceInfos;
    int32_t ret = proxy_->GetExternalStorageDeviceInfos(data, deviceInfos);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_TRUE(deviceInfos.empty());
}

/**
 * @tc.name: TestAddAllowedOddBurnUsbDevicesSuc
 * @tc.desc: Test AddAllowedOddBurnUsbDevices success func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestAddAllowedOddBurnUsbDevicesSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = proxy_->AddAllowedOddBurnUsbDevices(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddAllowedOddBurnUsbDevicesFail
 * @tc.desc: Test AddAllowedOddBurnUsbDevices without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestAddAllowedOddBurnUsbDevicesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    int32_t ret = proxy_->AddAllowedOddBurnUsbDevices(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveAllowedOddBurnUsbDevicesSuc
 * @tc.desc: Test RemoveAllowedOddBurnUsbDevices success func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestRemoveAllowedOddBurnUsbDevicesSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = proxy_->RemoveAllowedOddBurnUsbDevices(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveAllowedOddBurnUsbDevicesFail
 * @tc.desc: Test RemoveAllowedOddBurnUsbDevices without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestRemoveAllowedOddBurnUsbDevicesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    int32_t ret = proxy_->RemoveAllowedOddBurnUsbDevices(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetAllowedOddBurnUsbDevicesSuc
 * @tc.desc: Test GetAllowedOddBurnUsbDevices success func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestGetAllowedOddBurnUsbDevicesSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(),
            &EnterpriseDeviceMgrStubMock::InvokeOddBurnUsbDevicesSendRequestGetPolicy));

    MessageParcel reply;
    int32_t ret = proxy_->GetAllowedOddBurnUsbDevices(data, reply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetAllowedOddBurnUsbDevicesFail
 * @tc.desc: Test GetAllowedOddBurnUsbDevices without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestGetAllowedOddBurnUsbDevicesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);

    MessageParcel reply;
    int32_t ret = proxy_->GetAllowedOddBurnUsbDevices(data, reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetAllowedOddBurnUsbDevicesReplyFail
 * @tc.desc: Test GetAllowedOddBurnUsbDevices when reply contains error code.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, TestGetAllowedOddBurnUsbDevicesReplyFail, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestReplyFail));

    MessageParcel reply;
    int32_t ret = proxy_->GetAllowedOddBurnUsbDevices(data, reply);
    ASSERT_TRUE(ret != ERR_OK);
}

/**
 * @tc.name: IsAllowedOddBurn_Allowed_Success
 * @tc.desc: Test IsAllowedOddBurn when query returns allowed.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, IsAllowedOddBurn_Allowed_Success, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy));

    bool result = proxy_->IsAllowedOddBurn(TEST_ACCOUNT_ID, 1, 9, "serial1");
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsAllowedOddBurn_NotAllowed_Deny
 * @tc.desc: Test IsAllowedOddBurn when query returns not allowed.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, IsAllowedOddBurn_NotAllowed_Deny, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeBoolFalseSendRequestGetPolicy));

    bool result = proxy_->IsAllowedOddBurn(TEST_ACCOUNT_ID, 1, 9, "serial1");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsAllowedOddBurn_EdmDisabled_Allow
 * @tc.desc: Test IsAllowedOddBurn when edm service is disabled, device not under control.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, IsAllowedOddBurn_EdmDisabled_Allow, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    bool result = proxy_->IsAllowedOddBurn(TEST_ACCOUNT_ID, 1, 9, "serial1");
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsAllowedOddBurn_ReplyFail_Deny
 * @tc.desc: Test IsAllowedOddBurn when reply contains error code.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, IsAllowedOddBurn_ReplyFail_Deny, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestReplyFail));

    bool result = proxy_->IsAllowedOddBurn(TEST_ACCOUNT_ID, 1, 9, "serial1");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsAllowedOddBurn_SendRequestFail_Deny
 * @tc.desc: Test IsAllowedOddBurn when SendRequest fails.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, IsAllowedOddBurn_SendRequestFail_Deny, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestFail));

    bool result = proxy_->IsAllowedOddBurn(TEST_ACCOUNT_ID, 1, 9, "serial1");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: AddOddBurnForAccount_Set_Success
 * @tc.desc: Test AddOrRemoveAllowedOddBurnUsbDevicesForAccount SET success.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, AddOddBurnForAccount_Set_Success, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInterfaceToken(u"ohos.edm.IEnterpriseDeviceMgr");
    data.WriteInt32(TEST_ACCOUNT_ID);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = proxy_->AddOrRemoveAllowedOddBurnUsbDevicesForAccount(data, FuncOperateType::SET);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AddOddBurnForAccount_Remove_Success
 * @tc.desc: Test AddOrRemoveAllowedOddBurnUsbDevicesForAccount REMOVE success.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, AddOddBurnForAccount_Remove_Success, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInterfaceToken(u"ohos.edm.IEnterpriseDeviceMgr");
    data.WriteInt32(TEST_ACCOUNT_ID);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = proxy_->AddOrRemoveAllowedOddBurnUsbDevicesForAccount(data, FuncOperateType::REMOVE);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: AddOddBurnForAccount_EdmDisabled_Fail
 * @tc.desc: Test AddOrRemoveAllowedOddBurnUsbDevicesForAccount when edm is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, AddOddBurnForAccount_EdmDisabled_Fail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    data.WriteInterfaceToken(u"ohos.edm.IEnterpriseDeviceMgr");
    data.WriteInt32(TEST_ACCOUNT_ID);

    int32_t ret = proxy_->AddOrRemoveAllowedOddBurnUsbDevicesForAccount(data, FuncOperateType::SET);
    EXPECT_EQ(ret, EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: GetOddBurnForAccount_Success
 * @tc.desc: Test GetAllowedOddBurnUsbDevicesForAccount success and reply devices.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, GetOddBurnForAccount_Success, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInterfaceToken(u"ohos.edm.IEnterpriseDeviceMgr");
    data.WriteInt32(TEST_ACCOUNT_ID);
    data.WriteInt32(static_cast<int32_t>(QueryPolicy::SELF));
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(),
            &EnterpriseDeviceMgrStubMock::InvokeOddBurnUsbDevicesSendRequestGetPolicy));

    MessageParcel reply;
    int32_t ret = proxy_->GetAllowedOddBurnUsbDevicesForAccount(data, reply);
    ASSERT_EQ(ret, ERR_OK);
    std::vector<OddBurnUsbDevice> devices;
    ASSERT_TRUE(ArrayOddBurnUsbDeviceSerializer::GetInstance()->ReadRawDataFromParcel(reply, devices));
    EXPECT_EQ(devices.size(), 1u);
    EXPECT_EQ(devices[0].GetVendorId(), 1);
    EXPECT_EQ(devices[0].GetProductId(), 9);
}

/**
 * @tc.name: GetOddBurnForAccount_EdmDisabled_Fail
 * @tc.desc: Test GetAllowedOddBurnUsbDevicesForAccount when edm is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, GetOddBurnForAccount_EdmDisabled_Fail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    data.WriteInterfaceToken(u"ohos.edm.IEnterpriseDeviceMgr");
    data.WriteInt32(TEST_ACCOUNT_ID);
    data.WriteInt32(static_cast<int32_t>(QueryPolicy::SELF));

    MessageParcel reply;
    int32_t ret = proxy_->GetAllowedOddBurnUsbDevicesForAccount(data, reply);
    EXPECT_EQ(ret, EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: GetOddBurnForAccount_ReplyFail_Fail
 * @tc.desc: Test GetAllowedOddBurnUsbDevicesForAccount when reply contains error code.
 * @tc.type: FUNC
 */
HWTEST_F(UsbManagerProxyTest, GetOddBurnForAccount_ReplyFail_Fail, TestSize.Level1)
{
    MessageParcel data;
    data.WriteInterfaceToken(u"ohos.edm.IEnterpriseDeviceMgr");
    data.WriteInt32(TEST_ACCOUNT_ID);
    data.WriteInt32(static_cast<int32_t>(QueryPolicy::ALL));
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestReplyFail));

    MessageParcel reply;
    int32_t ret = proxy_->GetAllowedOddBurnUsbDevicesForAccount(data, reply);
    EXPECT_NE(ret, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
