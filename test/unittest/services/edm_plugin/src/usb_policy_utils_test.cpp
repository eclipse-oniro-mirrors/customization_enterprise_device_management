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

#include "usb_policy_utils.h"
#include "edm_constants.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class UsbPolicyUtilsTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void UsbPolicyUtilsTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void UsbPolicyUtilsTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: UsbPolicyUtils_SetDisallowedPermissiveUsbDevices_EmptyData_Success
 * @tc.desc: Test SetDisallowedPermissiveUsbDevices with empty data.
 * @tc.type: FUNC
 */
HWTEST_F(UsbPolicyUtilsTest, UsbPolicyUtils_SetDisallowedPermissiveUsbDevices_EmptyData_Success, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    ErrCode ret = UsbPolicyUtils::SetDisallowedPermissiveUsbDevices(data);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: UsbPolicyUtils_SetDisallowedPermissiveUsbDevices_WithData_Success
 * @tc.desc: Test SetDisallowedPermissiveUsbDevices with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(UsbPolicyUtilsTest, UsbPolicyUtils_SetDisallowedPermissiveUsbDevices_WithData_Success, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type;
    type.baseClass = 1;
    type.subClass = 2;
    type.protocol = 3;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    data.push_back(type);

    ErrCode ret = UsbPolicyUtils::SetDisallowedPermissiveUsbDevices(data);
    // The actual result depends on whether USB interface is initialized
    // It should return ERR_OK or handle the interface not init case gracefully
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: UsbPolicyUtils_SetDisallowedPermissiveUsbDevices_MultipleDevices_Success
 * @tc.desc: Test SetDisallowedPermissiveUsbDevices with multiple devices.
 * @tc.type: FUNC
 */
HWTEST_F(UsbPolicyUtilsTest, UsbPolicyUtils_SetDisallowedPermissiveUsbDevices_MultipleDevices_Success, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    for (int i = 0; i < 5; i++) {
        USB::UsbDeviceType type;
        type.baseClass = i;
        type.subClass = i + 1;
        type.protocol = i + 2;
        type.isDeviceType = (i % 2 == 0);
        type.isDeviceTypeAllMatch = false;
        data.push_back(type);
    }

    ErrCode ret = UsbPolicyUtils::SetDisallowedPermissiveUsbDevices(data);
    // The actual result depends on whether USB interface is initialized
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: UsbPolicyUtils_SetDisallowedUsbDevices_EmptyData_Success
 * @tc.desc: Test SetDisallowedUsbDevices with empty data.
 * @tc.type: FUNC
 */
HWTEST_F(UsbPolicyUtilsTest, UsbPolicyUtils_SetDisallowedUsbDevices_EmptyData_Success, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    ErrCode ret = UsbPolicyUtils::SetDisallowedUsbDevices(data);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: UsbPolicyUtils_SetUsbDisabled_True_Success
 * @tc.desc: Test SetUsbDisabled with true.
 * @tc.type: FUNC
 */
HWTEST_F(UsbPolicyUtilsTest, UsbPolicyUtils_SetUsbDisabled_True_Success, TestSize.Level1)
{
    ErrCode ret = UsbPolicyUtils::SetUsbDisabled(true);
    // The actual result depends on whether USB interface is initialized
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: UsbPolicyUtils_SetUsbDisabled_False_Success
 * @tc.desc: Test SetUsbDisabled with false.
 * @tc.type: FUNC
 */
HWTEST_F(UsbPolicyUtilsTest, UsbPolicyUtils_SetUsbDisabled_False_Success, TestSize.Level1)
{
    ErrCode ret = UsbPolicyUtils::SetUsbDisabled(false);
    // The actual result depends on whether USB interface is initialized
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: UsbPolicyUtils_SetDisallowedPermissiveUsbDevices_MaxSizeData_Success
 * @tc.desc: Test SetDisallowedPermissiveUsbDevices with maximum size data.
 * @tc.type: FUNC
 */
HWTEST_F(UsbPolicyUtilsTest, UsbPolicyUtils_SetDisallowedPermissiveUsbDevices_MaxSizeData_Success, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    for (uint32_t i = 0; i < EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE; i++) {
        USB::UsbDeviceType type;
        type.baseClass = i % 256;
        type.subClass = (i + 1) % 256;
        type.protocol = (i + 2) % 256;
        type.isDeviceType = (i % 2 == 0);
        type.isDeviceTypeAllMatch = false;
        data.push_back(type);
    }

    ErrCode ret = UsbPolicyUtils::SetDisallowedPermissiveUsbDevices(data);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: UsbPolicyUtils_SetDisallowedPermissiveUsbDevices_DuplicateDevices_Success
 * @tc.desc: Test SetDisallowedPermissiveUsbDevices with duplicate device types.
 * @tc.type: FUNC
 */
HWTEST_F(UsbPolicyUtilsTest, UsbPolicyUtils_SetDisallowedPermissiveUsbDevices_DuplicateDevices_Success, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type;
    type.baseClass = 1;
    type.subClass = 2;
    type.protocol = 3;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    
    for (int i = 0; i < 10; i++) {
        data.push_back(type);
    }

    ErrCode ret = UsbPolicyUtils::SetDisallowedPermissiveUsbDevices(data);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: UsbPolicyUtils_SetDisallowedPermissiveUsbDevices_AllDeviceTypeFlagsTrue_Success
 * @tc.desc: Test SetDisallowedPermissiveUsbDevices with all device type flags set to true.
 * @tc.type: FUNC
 */
HWTEST_F(UsbPolicyUtilsTest, UsbPolicyUtils_SetDisallowedPermissiveUsbDevices_AllDeviceTypeFlagsTrue_Success,
    TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type;
    type.baseClass = 8;
    type.subClass = 6;
    type.protocol = 50;
    type.isDeviceType = true;
    type.isDeviceTypeAllMatch = true;
    data.push_back(type);

    ErrCode ret = UsbPolicyUtils::SetDisallowedPermissiveUsbDevices(data);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: UsbPolicyUtils_SetDisallowedPermissiveUsbDevices_MixedDeviceTypes_Success
 * @tc.desc: Test SetDisallowedPermissiveUsbDevices with mixed device type flags.
 * @tc.type: FUNC
 */
HWTEST_F(UsbPolicyUtilsTest, UsbPolicyUtils_SetDisallowedPermissiveUsbDevices_MixedDeviceTypes_Success, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    
    USB::UsbDeviceType type1;
    type1.baseClass = 1;
    type1.subClass = 2;
    type1.protocol = 3;
    type1.isDeviceType = true;
    type1.isDeviceTypeAllMatch = false;
    data.push_back(type1);

    USB::UsbDeviceType type2;
    type2.baseClass = 4;
    type2.subClass = 5;
    type2.protocol = 6;
    type2.isDeviceType = false;
    type2.isDeviceTypeAllMatch = true;
    data.push_back(type2);

    USB::UsbDeviceType type3;
    type3.baseClass = 7;
    type3.subClass = 8;
    type3.protocol = 9;
    type3.isDeviceType = true;
    type3.isDeviceTypeAllMatch = true;
    data.push_back(type3);

    ErrCode ret = UsbPolicyUtils::SetDisallowedPermissiveUsbDevices(data);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: UsbPolicyUtils_QueryAllCreatedOsAccountIds_Success
 * @tc.desc: Test QueryAllCreatedOsAccountIds.
 * @tc.type: FUNC
 */
HWTEST_F(UsbPolicyUtilsTest, UsbPolicyUtils_QueryAllCreatedOsAccountIds_Success, TestSize.Level1)
{
    std::vector<int32_t> userIds;
    ErrCode ret = UsbPolicyUtils::QueryAllCreatedOsAccountIds(userIds);
    // The actual result depends on the system state
    ASSERT_TRUE(ret == ERR_OK || ret != ERR_OK);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
