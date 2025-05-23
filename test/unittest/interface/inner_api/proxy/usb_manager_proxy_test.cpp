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

#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
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
} // namespace TEST
} // namespace EDM
} // namespace OHOS
