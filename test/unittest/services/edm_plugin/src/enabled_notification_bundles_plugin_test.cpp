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

#include "enabled_notification_bundles_plugin_test.h"

#include <string>
#include <vector>

#include "edm_errors.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int32_t ACCOUNT_ID = 100;
constexpr size_t MAX_SIZE = 200;
} // namespace

class EnabledNotificationBundlesPluginMock : public EnabledNotificationBundlesPlugin {
public:
    std::vector<std::vector<std::string>> pushedLists_;
    std::vector<int32_t> pushedUserIds_;
    ErrCode pushRet_ = ERR_OK;

protected:
    ErrCode PushMergedList(const std::vector<std::string> &mergeData, int32_t userId) override
    {
        pushedLists_.push_back(mergeData);
        pushedUserIds_.push_back(userId);
        return pushRet_;
    }
};

void EnabledNotificationBundlesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void EnabledNotificationBundlesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnSetPolicy_001
 * @tc.desc: OnSetPolicy pushes the merged list and updates current and merge data.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnSetPolicy_001, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    std::vector<std::string> data = {"com.example.a"};
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, ACCOUNT_ID);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.pushedLists_.size(), 1U);
    EXPECT_EQ(plugin.pushedLists_[0].size(), 1U);
    EXPECT_EQ(plugin.pushedLists_[0][0], "com.example.a");
    EXPECT_EQ(plugin.pushedUserIds_[0], ACCOUNT_ID);
    EXPECT_EQ(currentData.size(), 1U);
    EXPECT_EQ(mergeData.size(), 1U);
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnSetPolicy_002
 * @tc.desc: OnSetPolicy keeps only one copy when the same bundle name is added twice.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnSetPolicy_002, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    std::vector<std::string> data = {"com.example.a"};
    std::vector<std::string> currentData = {"com.example.a"};
    std::vector<std::string> mergeData = {"com.example.a"};
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, ACCOUNT_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(currentData.size(), 1U);
    ASSERT_EQ(plugin.pushedLists_.size(), 1U);
    EXPECT_EQ(plugin.pushedLists_[0].size(), 1U);
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnSetPolicy_003
 * @tc.desc: OnSetPolicy merges the entries of other administrators with the entries of the caller.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnSetPolicy_003, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    std::vector<std::string> data = {"com.example.a"};
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData = {"com.example.b"};
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, ACCOUNT_ID);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.pushedLists_.size(), 1U);
    EXPECT_EQ(plugin.pushedLists_[0].size(), 2U);
    EXPECT_EQ(currentData.size(), 1U);
    EXPECT_EQ(mergeData.size(), 2U);
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnSetPolicy_004
 * @tc.desc: OnSetPolicy rejects an invalid account id without touching the notification service.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnSetPolicy_004, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    std::vector<std::string> data = {"com.example.a"};
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    EXPECT_EQ(plugin.OnSetPolicy(data, currentData, mergeData, 0), EdmReturnErrCode::UID_INVALID);
    EXPECT_EQ(plugin.OnSetPolicy(data, currentData, mergeData, -1), EdmReturnErrCode::UID_INVALID);
    EXPECT_TRUE(plugin.pushedLists_.empty());
    EXPECT_TRUE(currentData.empty());
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnSetPolicy_005
 * @tc.desc: OnSetPolicy does nothing when the input list is empty.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnSetPolicy_005, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    std::vector<std::string> data;
    std::vector<std::string> currentData = {"com.example.a"};
    std::vector<std::string> mergeData = {"com.example.a"};
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, ACCOUNT_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(plugin.pushedLists_.empty());
    EXPECT_EQ(currentData.size(), 1U);
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnSetPolicy_006
 * @tc.desc: OnSetPolicy rejects an input list larger than the maximum size.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnSetPolicy_006, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    std::vector<std::string> data;
    for (size_t i = 0; i <= MAX_SIZE; i++) {
        data.push_back("com.example." + std::to_string(i));
    }
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::POLICY_LIST_OVER_SIZE);
    EXPECT_TRUE(plugin.pushedLists_.empty());
    EXPECT_TRUE(currentData.empty());
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnSetPolicy_007
 * @tc.desc: OnSetPolicy rejects the request when the merged list exceeds the maximum size.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnSetPolicy_007, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    std::vector<std::string> currentData;
    for (size_t i = 0; i < MAX_SIZE - 50; i++) {
        currentData.push_back("com.example.current." + std::to_string(i));
    }
    std::vector<std::string> data;
    for (size_t i = 0; i < 60; i++) {
        data.push_back("com.example.new." + std::to_string(i));
    }
    std::vector<std::string> mergeData = currentData;
    size_t currentSize = currentData.size();
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::POLICY_LIST_OVER_SIZE);
    EXPECT_TRUE(plugin.pushedLists_.empty());
    EXPECT_EQ(currentData.size(), currentSize);
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnSetPolicy_008
 * @tc.desc: OnSetPolicy reports a timeout and keeps the policy data unchanged when the push fails.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnSetPolicy_008, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    plugin.pushRet_ = EdmReturnErrCode::EXECUTE_TIME_OUT;
    std::vector<std::string> data = {"com.example.a"};
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    EXPECT_TRUE(currentData.empty());
    EXPECT_TRUE(mergeData.empty());
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnRemovePolicy_001
 * @tc.desc: OnRemovePolicy removes only the entries owned by the caller.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnRemovePolicy_001, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    std::vector<std::string> data = {"com.example.a"};
    std::vector<std::string> currentData = {"com.example.a"};
    std::vector<std::string> mergeData = {"com.example.b"};
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, mergeData, ACCOUNT_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(currentData.empty());
    ASSERT_EQ(plugin.pushedLists_.size(), 1U);
    EXPECT_EQ(plugin.pushedLists_[0].size(), 1U);
    EXPECT_EQ(plugin.pushedLists_[0][0], "com.example.b");
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnRemovePolicy_002
 * @tc.desc: OnRemovePolicy keeps an entry that another administrator still holds.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnRemovePolicy_002, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    std::vector<std::string> data = {"com.example.b"};
    std::vector<std::string> currentData = {"com.example.a"};
    std::vector<std::string> mergeData = {"com.example.a", "com.example.b"};
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, mergeData, ACCOUNT_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(currentData.size(), 1U);
    ASSERT_EQ(plugin.pushedLists_.size(), 1U);
    EXPECT_EQ(plugin.pushedLists_[0].size(), 2U);
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnRemovePolicy_003
 * @tc.desc: OnRemovePolicy pushes an empty list when the last entry is removed.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnRemovePolicy_003, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    std::vector<std::string> data = {"com.example.a"};
    std::vector<std::string> currentData = {"com.example.a"};
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, mergeData, ACCOUNT_ID);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.pushedLists_.size(), 1U);
    EXPECT_TRUE(plugin.pushedLists_[0].empty());
    EXPECT_TRUE(currentData.empty());
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnRemovePolicy_004
 * @tc.desc: OnRemovePolicy rejects an invalid account id and does nothing for an empty input list.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnRemovePolicy_004, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    std::vector<std::string> data = {"com.example.a"};
    std::vector<std::string> currentData = {"com.example.a"};
    std::vector<std::string> mergeData = {"com.example.a"};
    EXPECT_EQ(plugin.OnRemovePolicy(data, currentData, mergeData, 0), EdmReturnErrCode::UID_INVALID);
    EXPECT_TRUE(plugin.pushedLists_.empty());
    std::vector<std::string> emptyData;
    EXPECT_EQ(plugin.OnRemovePolicy(emptyData, currentData, mergeData, ACCOUNT_ID), ERR_OK);
    EXPECT_TRUE(plugin.pushedLists_.empty());
    EXPECT_EQ(currentData.size(), 1U);
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnAdminRemove_001
 * @tc.desc: OnAdminRemove pushes the merged list without the entries of the removed administrator.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnAdminRemove_001, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    std::vector<std::string> data = {"com.example.a"};
    std::vector<std::string> mergeData = {"com.example.b"};
    ErrCode ret = plugin.OnAdminRemove("com.example.mdm", data, mergeData, ACCOUNT_ID);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(plugin.pushedLists_.size(), 1U);
    EXPECT_EQ(plugin.pushedLists_[0].size(), 1U);
    EXPECT_EQ(plugin.pushedLists_[0][0], "com.example.b");
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnAdminRemove_002
 * @tc.desc: OnAdminRemove returns an error when the notification service rejects the push.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnAdminRemove_002, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    plugin.pushRet_ = EdmReturnErrCode::EXECUTE_TIME_OUT;
    std::vector<std::string> data = {"com.example.a"};
    std::vector<std::string> mergeData = {"com.example.b"};
    ErrCode ret = plugin.OnAdminRemove("com.example.mdm", data, mergeData, ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    EXPECT_EQ(plugin.pushedLists_.size(), 1U);
}

/**
 * @tc.name: EnabledNotificationBundlesPluginTest.OnAdminRemove_003
 * @tc.desc: OnAdminRemove rejects an invalid account id.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesPluginTest, OnAdminRemove_003, TestSize.Level1)
{
    EnabledNotificationBundlesPluginMock plugin;
    std::vector<std::string> data;
    std::vector<std::string> mergeData;
    EXPECT_EQ(plugin.OnAdminRemove("com.example.mdm", data, mergeData, 0), EdmReturnErrCode::UID_INVALID);
    EXPECT_TRUE(plugin.pushedLists_.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
