#include <gtest/gtest.h>

#include "sensitive_call_notify_manager.h"
#include "sensitive_call_notify_rdb.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_ADMIN_NAME = "com.test.manager";
const std::string TEST_SENSITIVE_ID = "POLICY:1177";
const int32_t TEST_USER_ID = 100;
const int32_t TEST_APP_INDEX = 0;

class SensitiveCallNotifyManagerTest : public testing::Test {
public:
    void SetUp() override
    {
        manager_ = SensitiveCallNotifyManager::GetInstance();
        rdb_ = SensitiveCallNotifyRdb::GetInstance();
    }
    std::shared_ptr<SensitiveCallNotifyManager> manager_;
    std::shared_ptr<SensitiveCallNotifyRdb> rdb_;
};

/**
 * @tc.name: TestGetInstance_NotNull
 * @tc.desc: Test GetInstance returns a valid singleton.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveCallNotifyManagerTest, TestGetInstance_NotNull, TestSize.Level1)
{
    ASSERT_NE(manager_, nullptr);
    auto instance2 = SensitiveCallNotifyManager::GetInstance();
    EXPECT_NE(instance2, nullptr);
    EXPECT_EQ(manager_, instance2);
}

/**
 * @tc.name: TestClearByAdmin_DeletesRecord
 * @tc.desc: Test ClearByAdmin removes the record after insert.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveCallNotifyManagerTest, TestClearByAdmin_DeletesRecord, TestSize.Level1)
{
    ASSERT_NE(rdb_, nullptr);
    SensitiveCallRecord record;
    record.adminName = TEST_ADMIN_NAME;
    record.userId = TEST_USER_ID;
    record.appIndex = TEST_APP_INDEX;
    record.sensitiveId = TEST_SENSITIVE_ID;
    record.notifiedTime = 1000;
    EXPECT_TRUE(rdb_->Insert(record));
    EXPECT_TRUE(rdb_->Query(TEST_ADMIN_NAME, TEST_USER_ID, TEST_APP_INDEX, TEST_SENSITIVE_ID));

    manager_->ClearByAdmin(TEST_ADMIN_NAME, TEST_USER_ID);

    EXPECT_FALSE(rdb_->Query(TEST_ADMIN_NAME, TEST_USER_ID, TEST_APP_INDEX, TEST_SENSITIVE_ID));
}

/**
 * @tc.name: TestClearByAdmin_NonExistentAdmin_NoError
 * @tc.desc: Test ClearByAdmin with non-existent admin does not error.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveCallNotifyManagerTest, TestClearByAdmin_NonExistentAdmin_NoError, TestSize.Level1)
{
    ASSERT_NE(rdb_, nullptr);
    std::string nonExistentAdmin = "com.test.nonexistent.clearadmin";
    EXPECT_FALSE(rdb_->Query(nonExistentAdmin, TEST_USER_ID, TEST_APP_INDEX, TEST_SENSITIVE_ID));
    manager_->ClearByAdmin(nonExistentAdmin, TEST_USER_ID);
    EXPECT_FALSE(rdb_->Query(nonExistentAdmin, TEST_USER_ID, TEST_APP_INDEX, TEST_SENSITIVE_ID));
}

/**
 * @tc.name: TestClearByApp_DeletesRecord
 * @tc.desc: Test ClearByApp removes the record after insert.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveCallNotifyManagerTest, TestClearByApp_DeletesRecord, TestSize.Level1)
{
    ASSERT_NE(rdb_, nullptr);
    SensitiveCallRecord record;
    record.adminName = TEST_ADMIN_NAME;
    record.userId = TEST_USER_ID;
    record.appIndex = TEST_APP_INDEX;
    record.sensitiveId = TEST_SENSITIVE_ID;
    record.notifiedTime = 2000;
    EXPECT_TRUE(rdb_->Insert(record));
    EXPECT_TRUE(rdb_->Query(TEST_ADMIN_NAME, TEST_USER_ID, TEST_APP_INDEX, TEST_SENSITIVE_ID));

    manager_->ClearByApp(TEST_ADMIN_NAME, TEST_APP_INDEX);

    EXPECT_FALSE(rdb_->Query(TEST_ADMIN_NAME, TEST_USER_ID, TEST_APP_INDEX, TEST_SENSITIVE_ID));
}

/**
 * @tc.name: TestClearByApp_NonExistentApp_NoError
 * @tc.desc: Test ClearByApp with non-existent app does not error.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveCallNotifyManagerTest, TestClearByApp_NonExistentApp_NoError, TestSize.Level1)
{
    ASSERT_NE(rdb_, nullptr);
    std::string nonExistentApp = "com.test.nonexistent.clearapp";
    EXPECT_FALSE(rdb_->Query(nonExistentApp, TEST_USER_ID, TEST_APP_INDEX, TEST_SENSITIVE_ID));
    manager_->ClearByApp(nonExistentApp, TEST_APP_INDEX);
    EXPECT_FALSE(rdb_->Query(nonExistentApp, TEST_USER_ID, TEST_APP_INDEX, TEST_SENSITIVE_ID));
}

/**
 * @tc.name: TestClearByAdmin_PreservesOtherAdmins
 * @tc.desc: Test ClearByAdmin only deletes records for the specified admin.
 * @tc.type: FUNC
 */
HWTEST_F(SensitiveCallNotifyManagerTest, TestClearByAdmin_PreservesOtherAdmins, TestSize.Level1)
{
    ASSERT_NE(rdb_, nullptr);
    SensitiveCallRecord record1;
    record1.adminName = "com.test.admin1";
    record1.userId = TEST_USER_ID;
    record1.appIndex = TEST_APP_INDEX;
    record1.sensitiveId = TEST_SENSITIVE_ID;
    record1.notifiedTime = 3000;
    EXPECT_TRUE(rdb_->Insert(record1));

    SensitiveCallRecord record2;
    record2.adminName = "com.test.admin2";
    record2.userId = TEST_USER_ID;
    record2.appIndex = TEST_APP_INDEX;
    record2.sensitiveId = TEST_SENSITIVE_ID;
    record2.notifiedTime = 3001;
    EXPECT_TRUE(rdb_->Insert(record2));

    manager_->ClearByAdmin("com.test.admin1", TEST_USER_ID);

    EXPECT_FALSE(rdb_->Query("com.test.admin1", TEST_USER_ID, TEST_APP_INDEX, TEST_SENSITIVE_ID));
    EXPECT_TRUE(rdb_->Query("com.test.admin2", TEST_USER_ID, TEST_APP_INDEX, TEST_SENSITIVE_ID));

    rdb_->DeleteByAdmin("com.test.admin2", TEST_USER_ID);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
