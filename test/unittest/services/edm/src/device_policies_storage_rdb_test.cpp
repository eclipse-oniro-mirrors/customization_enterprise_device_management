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

#include "device_policies_storage_rdb.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const int DEFAULT_USER_ID = 100;
const int TEST_USER_ID = 101;
const std::string TEST_POLICY_NAME = "policyName";
const std::string TEST_POLICY_NAME2 = "policyName2";
const std::string TEST_POLICY_VALUE = "policyValue";
const std::string TEST_POLICY_VALUE2 = "policyValue2";
const std::string ADMIN_PACKAGENAME_ABLILITY = "com.edm.test.MainAbility";
class DevicePoliciesStorageRdbTest : public testing::Test {};
/**
 * @tc.name: TestQueryAllUserIdWithoutPolicy
 * @tc.desc: Test AdminManager::QueryAllUserId.
 * @tc.type: FUNC
 */
HWTEST_F(DevicePoliciesStorageRdbTest, TestQueryAllUserIdWithoutPolicy, TestSize.Level1)
{
    std::shared_ptr<DevicePoliciesStorageRdb> devicePoliciesStorageRdb = DevicePoliciesStorageRdb::GetInstance();
    std::vector<int32_t> userIds;
    devicePoliciesStorageRdb->QueryAllUserId(userIds);
    ASSERT_TRUE(userIds.empty());
}

/**
 * @tc.name: TestQueryAllUserIdWithPolicy
 * @tc.desc: Test AdminManager::QueryAllUserId.
 * @tc.type: FUNC
 */
HWTEST_F(DevicePoliciesStorageRdbTest, TestQueryAllUserIdWithPolicy, TestSize.Level1)
{
    std::shared_ptr<DevicePoliciesStorageRdb> devicePoliciesStorageRdb = DevicePoliciesStorageRdb::GetInstance();
    bool ret = devicePoliciesStorageRdb->InsertAdminPolicy(DEFAULT_USER_ID, ADMIN_PACKAGENAME_ABLILITY,
        TEST_POLICY_NAME, TEST_POLICY_VALUE);
    ASSERT_TRUE(ret);

    std::vector<int32_t> userIds;
    devicePoliciesStorageRdb->QueryAllUserId(userIds);
    ASSERT_TRUE(userIds.size() == 1);

    ret = devicePoliciesStorageRdb->DeleteAdminPolicy(DEFAULT_USER_ID, ADMIN_PACKAGENAME_ABLILITY, TEST_POLICY_NAME);
    ASSERT_TRUE(ret);

    userIds.clear();
    devicePoliciesStorageRdb->QueryAllUserId(userIds);
    ASSERT_TRUE(userIds.empty());
}

/**
 * @tc.name: TestQueryAllUserIdWithMultiPolicy
 * @tc.desc: Test AdminManager::QueryAllUserId.
 * @tc.type: FUNC
 */
HWTEST_F(DevicePoliciesStorageRdbTest, TestQueryAllUserIdWithMultiPolicy, TestSize.Level1)
{
    std::shared_ptr<DevicePoliciesStorageRdb> devicePoliciesStorageRdb = DevicePoliciesStorageRdb::GetInstance();
    bool ret = devicePoliciesStorageRdb->InsertAdminPolicy(DEFAULT_USER_ID, ADMIN_PACKAGENAME_ABLILITY,
        TEST_POLICY_NAME, TEST_POLICY_VALUE);
    ASSERT_TRUE(ret);
    ret = devicePoliciesStorageRdb->InsertCombinedPolicy(DEFAULT_USER_ID, TEST_POLICY_NAME2, TEST_POLICY_VALUE2);
    ASSERT_TRUE(ret);

    std::vector<int32_t> userIds;
    devicePoliciesStorageRdb->QueryAllUserId(userIds);
    ASSERT_TRUE(userIds.size() == 1);

    ret = devicePoliciesStorageRdb->DeleteAdminPolicy(DEFAULT_USER_ID, ADMIN_PACKAGENAME_ABLILITY, TEST_POLICY_NAME);
    ASSERT_TRUE(ret);

    ret = devicePoliciesStorageRdb->DeleteAdminPolicy(DEFAULT_USER_ID, ADMIN_PACKAGENAME_ABLILITY, TEST_POLICY_NAME2);
    ASSERT_TRUE(ret);

    userIds.clear();
    devicePoliciesStorageRdb->QueryAllUserId(userIds);
    ASSERT_TRUE(userIds.empty());
}

/**
 * @tc.name: TestQueryAllUserIdWithMultiUserId
 * @tc.desc: Test AdminManager::QueryAllUserId.
 * @tc.type: FUNC
 */
HWTEST_F(DevicePoliciesStorageRdbTest, TestQueryAllUserIdWithMultiUserId, TestSize.Level1)
{
    std::shared_ptr<DevicePoliciesStorageRdb> devicePoliciesStorageRdb = DevicePoliciesStorageRdb::GetInstance();
    bool ret = devicePoliciesStorageRdb->InsertAdminPolicy(DEFAULT_USER_ID, ADMIN_PACKAGENAME_ABLILITY,
        TEST_POLICY_NAME, TEST_POLICY_VALUE);
    ASSERT_TRUE(ret);
    ret = devicePoliciesStorageRdb->InsertAdminPolicy(TEST_USER_ID, ADMIN_PACKAGENAME_ABLILITY,
        TEST_POLICY_NAME, TEST_POLICY_VALUE);
    ASSERT_TRUE(ret);

    std::vector<int32_t> userIds;
    devicePoliciesStorageRdb->QueryAllUserId(userIds);
    ASSERT_TRUE(userIds.size() == 2);

    ret = devicePoliciesStorageRdb->DeleteAdminPolicy(DEFAULT_USER_ID, ADMIN_PACKAGENAME_ABLILITY, TEST_POLICY_NAME);
    ASSERT_TRUE(ret);

    ret = devicePoliciesStorageRdb->DeleteAdminPolicy(TEST_USER_ID, ADMIN_PACKAGENAME_ABLILITY, TEST_POLICY_NAME);
    ASSERT_TRUE(ret);

    userIds.clear();
    devicePoliciesStorageRdb->QueryAllUserId(userIds);
    ASSERT_TRUE(userIds.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
