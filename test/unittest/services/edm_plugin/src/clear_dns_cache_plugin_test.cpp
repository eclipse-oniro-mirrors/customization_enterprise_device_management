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

#define private public
#define protected public
#include "clear_dns_cache_plugin.h"
#undef protected
#undef private

#include "clear_dns_cache_plugin_test.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

void ClearDnsCachePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ClearDnsCachePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestConstructor
 * @tc.desc: Verify constructor sets policyCode, policyName, permissionConfig, needSave correctly.
 * @tc.type: FUNC
 */
HWTEST_F(ClearDnsCachePluginTest, TestConstructor, TestSize.Level1)
{
    ClearDnsCachePlugin plugin;
    EXPECT_EQ(plugin.policyCode_, EdmInterfaceCode::CLEAR_DNS_CACHE);
    EXPECT_EQ(plugin.policyName_, PolicyName::POLICY_CLEAR_DNS_CACHE);
    ASSERT_EQ(plugin.permissionConfig_.typePermissions.size(), 1u);
    EXPECT_EQ(plugin.permissionConfig_.typePermissions.at(IPlugin::PermissionType::SUPER_DEVICE_ADMIN),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK);
    EXPECT_EQ(plugin.permissionConfig_.apiType, IPlugin::ApiType::PUBLIC);
    EXPECT_FALSE(plugin.needSave_);
}

/**
 * @tc.name: TestOnHandlePolicy_ReadNetIdFail
 * @tc.desc: Empty data parcel causes ReadInt32 to fail, returns PARAMETER_VERIFICATION_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(ClearDnsCachePluginTest, TestOnHandlePolicy_ReadNetIdFail, TestSize.Level1)
{
    ClearDnsCachePlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData{"", "", false};
    ErrCode ret = plugin.OnHandlePolicy(0, data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicy_NegativeNetId
 * @tc.desc: netId = -1 is invalid, returns PARAMETER_VERIFICATION_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(ClearDnsCachePluginTest, TestOnHandlePolicy_NegativeNetId, TestSize.Level1)
{
    ClearDnsCachePlugin plugin;
    MessageParcel data;
    data.WriteInt32(-1);
    MessageParcel reply;
    HandlePolicyData policyData{"", "", false};
    ErrCode ret = plugin.OnHandlePolicy(0, data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicy_LargeNegativeNetId
 * @tc.desc: netId = INT32_MIN is invalid, returns PARAMETER_VERIFICATION_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(ClearDnsCachePluginTest, TestOnHandlePolicy_LargeNegativeNetId, TestSize.Level1)
{
    ClearDnsCachePlugin plugin;
    MessageParcel data;
    data.WriteInt32(INT32_MIN);
    MessageParcel reply;
    HandlePolicyData policyData{"", "", false};
    ErrCode ret = plugin.OnHandlePolicy(0, data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicy_ZeroNetId
 * @tc.desc: netId = 0 passes validation, proceeds to FlushDnsCache call.
 * @tc.type: FUNC
 */
HWTEST_F(ClearDnsCachePluginTest, TestOnHandlePolicy_ZeroNetId, TestSize.Level1)
{
    ClearDnsCachePlugin plugin;
    MessageParcel data;
    data.WriteInt32(0);
    MessageParcel reply;
    HandlePolicyData policyData{"", "", false};
    ErrCode ret = plugin.OnHandlePolicy(0, data, reply, policyData, DEFAULT_USER_ID);
    // netId=0 passes validation; FlushDnsCache may succeed or fail depending on UT env
    // Key assertion: must NOT return PARAMETER_VERIFICATION_FAILED (validation passed)
    EXPECT_NE(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicy_PositiveNetId
 * @tc.desc: netId = 100 passes validation, proceeds to FlushDnsCache call.
 * @tc.type: FUNC
 */
HWTEST_F(ClearDnsCachePluginTest, TestOnHandlePolicy_PositiveNetId, TestSize.Level1)
{
    ClearDnsCachePlugin plugin;
    MessageParcel data;
    data.WriteInt32(100);
    MessageParcel reply;
    HandlePolicyData policyData{"", "", false};
    ErrCode ret = plugin.OnHandlePolicy(0, data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_NE(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicy_MaxNetId
 * @tc.desc: netId = INT32_MAX passes validation, proceeds to FlushDnsCache call.
 * @tc.type: FUNC
 */
HWTEST_F(ClearDnsCachePluginTest, TestOnHandlePolicy_MaxNetId, TestSize.Level1)
{
    ClearDnsCachePlugin plugin;
    MessageParcel data;
    data.WriteInt32(INT32_MAX);
    MessageParcel reply;
    HandlePolicyData policyData{"", "", false};
    ErrCode ret = plugin.OnHandlePolicy(0, data, reply, policyData, DEFAULT_USER_ID);
    EXPECT_NE(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
