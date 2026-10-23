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

#include "sensitive_call_notify_rdb.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_ADMIN_NAME = "com.test.admin";
const std::string TEST_SENSITIVE_ID = "POLICY:1177";
const int32_t TEST_USER_ID = 100;
const int32_t TEST_APP_INDEX = 0;

class SensitiveCallNotifyRdbTest : public testing::Test {
public:
    void SetUp() override
    {
        rdb_ = SensitiveCallNotifyRdb::GetInstance();
    }
    std::shared_ptr<SensitiveCallNotifyRdb> rdb_;
};

/**
 * @tc.name: TestGetInstance_NotNull
 * @tc.desc: Test GetInstance returns a valid singleton.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveCallNotifyRdbTest, TestGetInstance_NotNull, TestSize.Level1)
{
    ASSERT_NE(rdb_, nullptr);
    auto instance2 = SensitiveCallNotifyRdb::GetInstance();
    EXPECT_NE(instance2, nullptr);
    EXPECT_EQ(rdb_, instance2);
}

/**
 * @tc.name: TestInsertAndQuery_RecordExists
 * @tc.desc: Test Insert then Query returns true for existing record.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveCallNotifyRdbTest, TestInsertAndQuery_RecordExists, TestSize.Level1)
{
    ASSERT_NE(rdb_, nullptr);
    SensitiveCallRecord record;
    record.adminName = TEST_ADMIN_NAME;
    record.userId = TEST_USER_ID;
    record.appIndex = TEST_APP_INDEX;
    record.sensitiveId = TEST_SENSITIVE_ID;
    record.notifiedTime = 1000;
    EXPECT_TRUE(rdb_->Insert(record));

    bool exists = rdb_->Query(TEST_ADMIN_NAME, TEST_USER_ID, TEST_APP_INDEX, TEST_SENSITIVE_ID);
    EXPECT_TRUE(exists);
}

/**
 * @tc.name: TestQuery_NonExistentRecord_ReturnFalse
 * @tc.desc: Test Query returns false for non-existent record.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveCallNotifyRdbTest, TestQuery_NonExistentRecord_ReturnFalse, TestSize.Level1)
{
    ASSERT_NE(rdb_, nullptr);
    std::string nonExistentAdmin = "com.test.nonexistent";
    std::string nonExistentId = "POLICY:9999";
    bool exists = rdb_->Query(nonExistentAdmin, TEST_USER_ID, TEST_APP_INDEX, nonExistentId);
    EXPECT_FALSE(exists);
    EXPECT_FALSE(rdb_->Query("", TEST_USER_ID, TEST_APP_INDEX, ""));
}

/**
 * @tc.name: TestInsert_DuplicateRecord_Idempotent
 * @tc.desc: Test Insert with same unique key is idempotent (no duplicate rows).
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveCallNotifyRdbTest, TestInsert_DuplicateRecord_Idempotent, TestSize.Level1)
{
    ASSERT_NE(rdb_, nullptr);
    SensitiveCallRecord record;
    record.adminName = "com.test.dup";
    record.userId = TEST_USER_ID;
    record.appIndex = TEST_APP_INDEX;
    record.sensitiveId = "POLICY:2001";
    record.notifiedTime = 2000;
    EXPECT_TRUE(rdb_->Insert(record));
    EXPECT_TRUE(rdb_->Insert(record));

    bool exists = rdb_->Query("com.test.dup", TEST_USER_ID, TEST_APP_INDEX, "POLICY:2001");
    EXPECT_TRUE(exists);
}

/**
 * @tc.name: TestDeleteByAdmin_RecordDeleted
 * @tc.desc: Test DeleteByAdmin removes the record.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveCallNotifyRdbTest, TestDeleteByAdmin_RecordDeleted, TestSize.Level1)
{
    ASSERT_NE(rdb_, nullptr);
    SensitiveCallRecord record;
    record.adminName = "com.test.deleteadmin";
    record.userId = TEST_USER_ID;
    record.appIndex = TEST_APP_INDEX;
    record.sensitiveId = "POLICY:3001";
    record.notifiedTime = 3000;
    EXPECT_TRUE(rdb_->Insert(record));
    EXPECT_TRUE(rdb_->DeleteByAdmin("com.test.deleteadmin", TEST_USER_ID));

    bool exists = rdb_->Query("com.test.deleteadmin", TEST_USER_ID, TEST_APP_INDEX, "POLICY:3001");
    EXPECT_FALSE(exists);
}

/**
 * @tc.name: TestDeleteByApp_RecordDeleted
 * @tc.desc: Test DeleteByApp removes the record.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveCallNotifyRdbTest, TestDeleteByApp_RecordDeleted, TestSize.Level1)
{
    ASSERT_NE(rdb_, nullptr);
    SensitiveCallRecord record;
    record.adminName = "com.test.deleteapp";
    record.userId = TEST_USER_ID;
    record.appIndex = TEST_APP_INDEX;
    record.sensitiveId = "POLICY:4001";
    record.notifiedTime = 4000;
    EXPECT_TRUE(rdb_->Insert(record));
    EXPECT_TRUE(rdb_->DeleteByApp("com.test.deleteapp", TEST_APP_INDEX));

    bool exists = rdb_->Query("com.test.deleteapp", TEST_USER_ID, TEST_APP_INDEX, "POLICY:4001");
    EXPECT_FALSE(exists);
}

/**
 * @tc.name: TestDeleteByAdmin_NonExistent_NoError
 * @tc.desc: Test DeleteByAdmin on non-existent admin does not error.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveCallNotifyRdbTest, TestDeleteByAdmin_NonExistent_NoError, TestSize.Level1)
{
    ASSERT_NE(rdb_, nullptr);
    std::string nonExistentAdmin = "com.test.nondeleteme";
    bool result = rdb_->DeleteByAdmin(nonExistentAdmin, TEST_USER_ID);
    EXPECT_TRUE(result);
    bool exists = rdb_->Query(nonExistentAdmin, TEST_USER_ID, TEST_APP_INDEX, TEST_SENSITIVE_ID);
    EXPECT_FALSE(exists);
}

/**
 * @tc.name: TestInsert_DifferentSensitiveIds_BothExist
 * @tc.desc: Test Insert with different sensitiveIds for same admin.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveCallNotifyRdbTest, TestInsert_DifferentSensitiveIds_BothExist, TestSize.Level1)
{
    ASSERT_NE(rdb_, nullptr);
    SensitiveCallRecord record1;
    record1.adminName = "com.test.multi";
    record1.userId = TEST_USER_ID;
    record1.appIndex = TEST_APP_INDEX;
    record1.sensitiveId = "POLICY:5001";
    record1.notifiedTime = 5000;
    EXPECT_TRUE(rdb_->Insert(record1));

    SensitiveCallRecord record2;
    record2.adminName = "com.test.multi";
    record2.userId = TEST_USER_ID;
    record2.appIndex = TEST_APP_INDEX;
    record2.sensitiveId = "POLICY:5002";
    record2.notifiedTime = 5001;
    EXPECT_TRUE(rdb_->Insert(record2));

    EXPECT_TRUE(rdb_->Query("com.test.multi", TEST_USER_ID, TEST_APP_INDEX, "POLICY:5001"));
    EXPECT_TRUE(rdb_->Query("com.test.multi", TEST_USER_ID, TEST_APP_INDEX, "POLICY:5002"));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
