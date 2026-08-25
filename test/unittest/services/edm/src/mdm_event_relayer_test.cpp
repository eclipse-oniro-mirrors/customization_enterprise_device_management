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
#include "mdm_event_relayer.h"
#undef private

#include <gtest/gtest.h>
#include <string>

#include "managed_event.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class MdmEventRelayerTest : public testing::Test {
protected:
    void SetUp() override
    {
        relayer_ = &MdmEventRelayer::GetInstance();
    }

    MdmEventRelayer *relayer_;
};

/**
 * @tc.name: Test_MakeAdminKeyCorrectFormat
 * @tc.desc: Test MakeAdminKey produces "adminName_userId" format.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, MakeAdminKey_CorrectFormat, TestSize.Level1)
{
    std::string key = relayer_->MakeAdminKey("com.test.admin", 100);
    EXPECT_EQ(key, "com.test.admin_100");
}

/**
 * @tc.name: Test_MakeAdminKeyDifferentUserIdDifferentKey
 * @tc.desc: Test MakeAdminKey produces different keys for different user IDs.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, MakeAdminKey_DifferentUserId_DifferentKey, TestSize.Level1)
{
    std::string key1 = relayer_->MakeAdminKey("com.test.admin", 100);
    std::string key2 = relayer_->MakeAdminKey("com.test.admin", 200);
    EXPECT_NE(key1, key2);
}

/**
 * @tc.name: Test_MakeAdminKeyDifferentAdminDifferentKey
 * @tc.desc: Test MakeAdminKey produces different keys for different admin names.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, MakeAdminKey_DifferentAdmin_DifferentKey, TestSize.Level1)
{
    std::string key1 = relayer_->MakeAdminKey("com.test.admin1", 100);
    std::string key2 = relayer_->MakeAdminKey("com.test.admin2", 100);
    EXPECT_NE(key1, key2);
}

/**
 * @tc.name: Test_OnAdminSubscribeCreatesHandle
 * @tc.desc: Test OnAdminSubscribe stores a subscription handle in the map.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, OnAdminSubscribe_CreatesHandle, TestSize.Level1)
{
    std::string admin = "com.test.sub_admin_" + std::to_string(std::rand());
    int32_t userId = 100;
    relayer_->OnAdminSubscribe(admin, userId, ManagedEvent::BUNDLE_ADDED);

    std::string key = relayer_->MakeAdminKey(admin, userId);
    auto adminIt = relayer_->adminSubscriptionHandles_.find(key);
    ASSERT_NE(adminIt, relayer_->adminSubscriptionHandles_.end());
    EXPECT_EQ(adminIt->second.count(ManagedEvent::BUNDLE_ADDED), 1u);
    EXPECT_NE(adminIt->second[ManagedEvent::BUNDLE_ADDED], nullptr);

    relayer_->OnAdminUnsubscribe(admin, userId, ManagedEvent::BUNDLE_ADDED);
}

/**
 * @tc.name: Test_OnAdminSubscribeDuplicateSkips
 * @tc.desc: Test OnAdminSubscribe skips when already subscribed to the same event.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, OnAdminSubscribe_Duplicate_Skips, TestSize.Level1)
{
    std::string admin = "com.test.dup_admin_" + std::to_string(std::rand());
    int32_t userId = 100;
    relayer_->OnAdminSubscribe(admin, userId, ManagedEvent::USER_SWITCHED);
    relayer_->OnAdminSubscribe(admin, userId, ManagedEvent::USER_SWITCHED);

    std::string key = relayer_->MakeAdminKey(admin, userId);
    EXPECT_EQ(relayer_->adminSubscriptionHandles_[key].count(ManagedEvent::USER_SWITCHED), 1u);

    relayer_->OnAdminUnsubscribe(admin, userId, ManagedEvent::USER_SWITCHED);
}

/**
 * @tc.name: Test_OnAdminUnsubscribeRemovesHandle
 * @tc.desc: Test OnAdminUnsubscribe removes the handle from the map.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, OnAdminUnsubscribe_RemovesHandle, TestSize.Level1)
{
    std::string admin = "com.test.unsub_admin_" + std::to_string(std::rand());
    int32_t userId = 100;
    relayer_->OnAdminSubscribe(admin, userId, ManagedEvent::BUNDLE_REMOVED);
    relayer_->OnAdminUnsubscribe(admin, userId, ManagedEvent::BUNDLE_REMOVED);

    std::string key = relayer_->MakeAdminKey(admin, userId);
    auto adminIt = relayer_->adminSubscriptionHandles_.find(key);
    if (adminIt != relayer_->adminSubscriptionHandles_.end()) {
        EXPECT_EQ(adminIt->second.count(ManagedEvent::BUNDLE_REMOVED), 0u);
    }
}

/**
 * @tc.name: Test_OnAdminRemovedClearsAllEvents
 * @tc.desc: Test OnAdminRemoved removes all subscription handles for an admin.
 * @tc.type: FUNC
 */
HWTEST_F(MdmEventRelayerTest, OnAdminRemoved_ClearsAllEvents, TestSize.Level1)
{
    std::string admin = "com.test.removed_admin_" + std::to_string(std::rand());
    int32_t userId = 100;
    relayer_->OnAdminSubscribe(admin, userId, ManagedEvent::BUNDLE_ADDED);
    relayer_->OnAdminSubscribe(admin, userId, ManagedEvent::USER_SWITCHED);

    std::string key = relayer_->MakeAdminKey(admin, userId);
    ASSERT_EQ(relayer_->adminSubscriptionHandles_.count(key), 1u);
    EXPECT_EQ(relayer_->adminSubscriptionHandles_[key].size(), 2u);

    relayer_->OnAdminRemoved(admin, userId);

    EXPECT_EQ(relayer_->adminSubscriptionHandles_.count(key), 0u);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
