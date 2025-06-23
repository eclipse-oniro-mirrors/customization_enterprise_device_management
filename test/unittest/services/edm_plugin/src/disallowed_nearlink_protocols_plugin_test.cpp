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

#include <gtest/gtest.h>

#include "disallowed_nearlink_protocols_plugin.h"

#include "edm_constants.h"
#include "edm_data_ability_utils_mock.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisallowedNearlinkProtocolsPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowedNearlinkProtocolsPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}
void DisallowedNearlinkProtocolsPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSetDisallowedNearlinkProtocolsEmpty
 * @tc.desc: Test set disallowed nearlink protocols function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedNearlinkProtocolsPluginTest, TestSetDisallowedNearlinkProtocolsEmpty, TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    DisallowedNearlinkProtocolsPlugin plugin;
    std::vector<std::int32_t> policyData;
    std::vector<std::int32_t> currentData;
    std::vector<std::int32_t> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestSetDisallowedNearlinkProtocolsWithDataAndCurrentData
 * @tc.desc: Test DisallowedNearlinkProtocolsPluginTest::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedNearlinkProtocolsPluginTest, TestSetDisallowedNearlinkProtocolsWithDataAndCurrentData,
TestSize.Level1)
{
    Utils::SetBluetoothEnable();
    DisallowedNearlinkProtocolsPlugin plugin;
    std::vector<std::int32_t> policyData = { 0, 1};
    std::vector<std::int32_t> currentData;
    std::vector<std::int32_t> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    plugin.OnChangedPolicyDone(true);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveDisallowedNearlinkProtocolsEmpty
 * @tc.desc: Test DisallowedNearlinkProtocolsPluginTest::OnRemovePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedNearlinkProtocolsPluginTest, TestRemoveDisallowedNearlinkProtocolsEmpty, TestSize.Level1)
{
    DisallowedNearlinkProtocolsPlugin plugin;
    std::vector<std::int32_t> policyData;
    std::vector<std::int32_t> currentData;
    std::vector<std::int32_t> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestRemoveDisallowedNearlinkProtocolsWithDataAndCurrentData
 * @tc.desc: Test DisallowedNearlinkProtocolsPluginTest::OnRemovePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedNearlinkProtocolsPluginTest, TestRemoveDisallowedNearlinkProtocolsWithDataAndCurrentData,
    TestSize.Level1)
{
    DisallowedNearlinkProtocolsPlugin plugin;
    std::vector<std::int32_t> policyData = { 0, 1 };
    std::vector<std::int32_t> currentData;
    std::vector<std::int32_t> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    plugin.OnChangedPolicyDone(false);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAdminRemoveDisallowedNearlinkProtocolsEmpty
 * @tc.desc: Test DisallowedNearlinkProtocolsPluginTest::OnAdminRemovePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedNearlinkProtocolsPluginTest, TestAdminRemoveDisallowedNearlinkProtocolsEmpty, TestSize.Level1)
{
    DisallowedNearlinkProtocolsPlugin plugin;
    std::string adminName{"testAdminName"};
    std::vector<std::int32_t> policyData;
    std::vector<std::int32_t> mergeData;
    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetPolicyDisallowedNearlinkProtocolsEmpty
 * @tc.desc: Test DisallowedNearlinkProtocolsPluginTest::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedNearlinkProtocolsPluginTest, TestGetPolicyDisallowedNearlinkProtocolsEmpty, TestSize.Level1)
{
    DisallowedNearlinkProtocolsPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
}
}
}