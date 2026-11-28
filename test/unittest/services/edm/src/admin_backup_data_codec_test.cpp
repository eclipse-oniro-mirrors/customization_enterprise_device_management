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

#include "admin_backup_data_codec.h"
#include "admin_type.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {

class AdminBackupDataCodecTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SerializeDeserialize_001
 * @tc.desc: Verify serialize then deserialize round-trips the payload.
 * @tc.type: FUNC
 */
HWTEST_F(AdminBackupDataCodecTest, SerializeDeserialize_001, TestSize.Level1)
{
    BackupPayload payload;
    payload.version = 1;
    AdminBackupItem item;
    item.bundleName = "com.test.admin";
    item.abilityName = "TestAdminExtAbility";
    item.userId = 100;
    item.adminType = static_cast<int32_t>(AdminType::NORMAL);
    item.enableSource = 0; // DEPLOY
    item.isDebug = false;
    payload.admins.push_back(item);

    std::vector<uint8_t> bytes;
    ASSERT_TRUE(AdminBackupDataCodec::GetInstance()->Serialize(payload, bytes));
    ASSERT_FALSE(bytes.empty());

    BackupPayload out;
    ASSERT_TRUE(AdminBackupDataCodec::GetInstance()->Deserialize(bytes, out));
    ASSERT_EQ(out.version, 1);
    ASSERT_EQ(out.admins.size(), 1u);
    ASSERT_EQ(out.admins[0].bundleName, "com.test.admin");
    ASSERT_EQ(out.admins[0].abilityName, "TestAdminExtAbility");
    ASSERT_EQ(out.admins[0].userId, 100);
    ASSERT_EQ(out.admins[0].adminType, static_cast<int32_t>(AdminType::NORMAL));
    ASSERT_EQ(out.admins[0].enableSource, 0);
    ASSERT_FALSE(out.admins[0].isDebug);
}

/**
 * @tc.name: AdminTypeToString_001
 * @tc.desc: Verify admin type to string mapping.
 * @tc.type: FUNC
 */
HWTEST_F(AdminBackupDataCodecTest, AdminTypeToString_001, TestSize.Level1)
{
    ASSERT_EQ(AdminBackupDataCodec::AdminTypeToString(static_cast<int32_t>(AdminType::ENT)), "SDA");
    ASSERT_EQ(AdminBackupDataCodec::AdminTypeToString(static_cast<int32_t>(AdminType::NORMAL)), "DA");
}

/**
 * @tc.name: SerializeBackupResult_001
 * @tc.desc: Verify backup result serialization.
 * @tc.type: FUNC
 */
HWTEST_F(AdminBackupDataCodecTest, SerializeBackupResult_001, TestSize.Level1)
{
    BackupResult result{0, "", 2};
    std::string json = AdminBackupDataCodec::GetInstance()->SerializeBackupResult(result);
    ASSERT_FALSE(json.empty());
}

/**
 * @tc.name: SerializeRestoreSummary_001
 * @tc.desc: Verify restore summary serialization.
 * @tc.type: FUNC
 */
HWTEST_F(AdminBackupDataCodecTest, SerializeRestoreSummary_001, TestSize.Level1)
{
    RestoreSummary summary;
    summary.succeeded = 1;
    summary.failed = 0;
    std::string json = AdminBackupDataCodec::GetInstance()->SerializeRestoreSummary(summary);
    ASSERT_FALSE(json.empty());
}

/**
 * @tc.name: Deserialize_001
 * @tc.desc: Deserialize empty bytes returns false.
 * @tc.type: FUNC
 */
HWTEST_F(AdminBackupDataCodecTest, Deserialize_001, TestSize.Level1)
{
    std::vector<uint8_t> empty;
    BackupPayload out;
    ASSERT_FALSE(AdminBackupDataCodec::GetInstance()->Deserialize(empty, out));
}

/**
 * @tc.name: Deserialize_002
 * @tc.desc: Deserialize rejects a payload whose version is not in the supported whitelist.
 * @tc.type: FUNC
 */
HWTEST_F(AdminBackupDataCodecTest, Deserialize_002, TestSize.Level1)
{
    std::string json = R"({"version":2,"deviceId":"x","admins":[]})";
    std::vector<uint8_t> bytes(json.begin(), json.end());
    BackupPayload out;
    ASSERT_FALSE(AdminBackupDataCodec::GetInstance()->Deserialize(bytes, out));
}

/**
 * @tc.name: Deserialize_003
 * @tc.desc: Deserialize rejects a payload missing the admins array.
 * @tc.type: FUNC
 */
HWTEST_F(AdminBackupDataCodecTest, Deserialize_003, TestSize.Level1)
{
    std::string json = R"({"version":1,"deviceId":"x"})";
    std::vector<uint8_t> bytes(json.begin(), json.end());
    BackupPayload out;
    ASSERT_FALSE(AdminBackupDataCodec::GetInstance()->Deserialize(bytes, out));
}

} // namespace EDM
} // namespace OHOS
