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

#include <fcntl.h>
#include <unistd.h>

#include <string>

#include "admin_manager.h"
#include "cJSON.h"
#include "edm_errors.h"
#include "message_parcel.h"
#include "utils.h"

#define private public
#include "backup_extension_handler.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace EDM {

class BackupExtensionHandlerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        TEST::Utils::SetEdmInitialEnv();
        AdminManager::GetInstance()->ClearAdmins();
    }

    void TearDown() override
    {
        TEST::Utils::ResetTokenTypeAndUid();
        ASSERT_TRUE(TEST::Utils::IsOriginalUTEnv());
    }
};

/**
 * @tc.name: GetInstance_001
 * @tc.desc: Verify GetInstance returns non-null singleton.
 * @tc.type: FUNC
 */
HWTEST_F(BackupExtensionHandlerTest, GetInstance_001, TestSize.Level1)
{
    auto* instance = BackupExtensionHandler::GetInstance();
    ASSERT_NE(instance, nullptr);
    ASSERT_EQ(instance, BackupExtensionHandler::GetInstance());
}

/**
 * @tc.name: OnBackup_EmptyAdmins_001
 * @tc.desc: OnBackup with no activated admin replies a valid fd of an empty backup file and
 *           a BackupResult JSON with errorCode 0 and adminCount 0.
 * @tc.type: FUNC
 */
HWTEST_F(BackupExtensionHandlerTest, OnBackup_EmptyAdmins_001, TestSize.Level1)
{
    MessageParcel data;
    ASSERT_TRUE(data.WriteString("backupInfo"));
    MessageParcel reply;
    ErrCode ret = BackupExtensionHandler::GetInstance()->OnBackup(data, reply);
    ASSERT_EQ(ret, ERR_OK);

    int32_t fd = reply.ReadFileDescriptor();
    ASSERT_GE(fd, 0);
    char buf[1] = {0};
    ASSERT_EQ(read(fd, buf, sizeof(buf)), 0);
    close(fd);
    std::string resultJson = reply.ReadString();
    ASSERT_FALSE(resultJson.empty());
    cJSON *root = cJSON_Parse(resultJson.c_str());
    ASSERT_NE(root, nullptr);
    cJSON *resultInfo = cJSON_GetObjectItem(root, "resultInfo");
    ASSERT_TRUE(cJSON_IsArray(resultInfo));

    cJSON *errorObj = cJSON_GetArrayItem(resultInfo, 0);
    ASSERT_NE(errorObj, nullptr);
    cJSON *type = cJSON_GetObjectItem(errorObj, "type");
    ASSERT_TRUE(cJSON_IsString(type));
    ASSERT_STREQ(type->valuestring, "ErrorInfo");
    cJSON *errorCode = cJSON_GetObjectItem(errorObj, "errorCode");
    ASSERT_TRUE(cJSON_IsString(errorCode));
    ASSERT_STREQ(errorCode->valuestring, "0");

    cJSON *countObj = cJSON_GetArrayItem(resultInfo, 1);
    ASSERT_NE(countObj, nullptr);
    type = cJSON_GetObjectItem(countObj, "type");
    ASSERT_TRUE(cJSON_IsString(type));
    ASSERT_STREQ(type->valuestring, "CountInfo");
    cJSON *infos = cJSON_GetObjectItem(countObj, "infos");
    ASSERT_TRUE(cJSON_IsArray(infos));
    cJSON *info = cJSON_GetArrayItem(infos, 0);
    ASSERT_NE(info, nullptr);
    cJSON *backupInfo = cJSON_GetObjectItem(info, "backupInfo");
    ASSERT_TRUE(cJSON_IsString(backupInfo));
    ASSERT_STREQ(backupInfo->valuestring, "edmAdmin");
    cJSON *successCount = cJSON_GetObjectItem(info, "successCount");
    ASSERT_TRUE(cJSON_IsNumber(successCount));
    ASSERT_EQ(successCount->valueint, 0);
    cJSON_Delete(root);
}

/**
 * @tc.name: CollectBackupAdmins_001
 * @tc.desc: CollectBackupAdmins stamps payload version and collects nothing when
 *           no admin is activated in the current environment.
 * @tc.type: FUNC
 */
HWTEST_F(BackupExtensionHandlerTest, CollectBackupAdmins_001, TestSize.Level1)
{
    BackupPayload payload;
    payload.version = 0;
    BackupExtensionHandler::GetInstance()->CollectBackupAdmins(payload);
    ASSERT_EQ(payload.version, 1);
    ASSERT_TRUE(payload.admins.empty());
}

} // namespace EDM
} // namespace OHOS

