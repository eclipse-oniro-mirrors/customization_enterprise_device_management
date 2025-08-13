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
#include <gtest/gtest.h>
#include "set_permission_managed_state_plugin.h"
#include "permission_managed_state_serializer.h"
#include "permission_managed_state_info.h"
#include "utils.h"
 
using namespace testing::ext;
 
namespace OHOS {
namespace EDM {
namespace TEST {
class SetPermissionManagedStatePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
 
    static void TearDownTestSuite(void);
};
const std::string POLICY_DATA = "[{\"tokenId\":1,\"clipboardPolicy\":1},{\"tokenId\":2,\"clipboardPolicy\":2}]";
void SetPermissionManagedStatePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}
 
void SetPermissionManagedStatePluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}
 
/**
 * @tc.name: TestOnSetPolicyEmpty
 * @tc.desc: Test SetPermissionManagedStatePluginTest::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(SetPermissionManagedStatePluginTest, TestOnSetPolicyEmpty, TestSize.Level1)
{
    SetPermissionManagedStatePlugin plugin;
    std::map<std::string, PermissionManagedStateInfo> data;
    std::map<std::string, PermissionManagedStateInfo> currentData;
    std::map<std::string, PermissionManagedStateInfo> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, 0);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}
 
/**
 * @tc.name: TestOnSetPolicyWithInvalidInfo
 * @tc.desc: Test SetPermissionManagedStatePluginTest::OnSetPolicy with invalid info.
 * @tc.type: FUNC
 */
HWTEST_F(SetPermissionManagedStatePluginTest, TestOnSetPolicyWithInvalidInfo, TestSize.Level1)
{
    SetPermissionManagedStatePlugin plugin;
    std::map<std::string, PermissionManagedStateInfo> data;
    PermissionManagedStateInfo info;
    info.appIdentifier = "0";
    info.permissionName = "ohos.permission.CAMERA";
    info.accountId = 0;
    info.tokenId = 0;
    info.appIndex = 0;
    info.managedState = static_cast<int32_t>(ManagedState::GRANTED);
    data.insert(std::make_pair("1", info));
    std::map<std::string, PermissionManagedStateInfo> currentData;
    std::map<std::string, PermissionManagedStateInfo> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, 0);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}
 
/**
 * @tc.name: TestOnAdminRemoveWithInvalidInfo
 * @tc.desc: Test SetPermissionManagedStatePluginTest::OnAdminRemove with invalid info.
 * @tc.type: FUNC
 */
HWTEST_F(SetPermissionManagedStatePluginTest, TestOnAdminRemoveWithInvalidInfo, TestSize.Level1)
{
    SetPermissionManagedStatePlugin plugin;
    std::map<std::string, PermissionManagedStateInfo> data;
    PermissionManagedStateInfo info;
    info.appIdentifier = "0";
    info.permissionName = "ohos.permission.CAMERA";
    info.accountId = 0;
    info.tokenId = 0;
    info.appIndex = 0;
    info.managedState = static_cast<int32_t>(ManagedState::GRANTED);
    data.insert(std::make_pair("1", info));
    std::map<std::string, PermissionManagedStateInfo> mergeData;
    ErrCode ret = plugin.OnAdminRemove("", data, mergeData, 0);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}
 
} // namespace TEST
} // namespace EDM
} // namespace OHOS