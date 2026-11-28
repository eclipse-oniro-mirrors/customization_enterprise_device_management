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
#include <vector>

#include "admin.h"
#include "admin_container.h"
#include "admin_type.h"
#include "cJSON.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "ent_info.h"
#include "message_parcel.h"
#include "utils.h"

#define private public
#include "restore_extension_handler.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace EDM {

class RestoreExtensionHandlerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        TEST::Utils::SetEdmInitialEnv();
    }

    void TearDown() override
    {
        TEST::Utils::ResetTokenTypeAndUid();
        ASSERT_TRUE(TEST::Utils::IsOriginalUTEnv());
    }

    int32_t PipeWithContent(const std::string &content)
    {
        int32_t fds[2] = { -1, -1 };
        EXPECT_EQ(pipe(fds), 0);
        ssize_t written = write(fds[1], content.data(), content.size());
        EXPECT_EQ(written, static_cast<ssize_t>(content.size()));
        close(fds[1]);
        return fds[0];
    }

    void SeedAdmin(const std::string &bundleName, int32_t userId, int32_t adminType, bool isDebug)
    {
        EntInfo entInfo("test", "test");
        std::vector<std::string> permissions;
        AdminInfo adminInfo = { .packageName_ = bundleName, .className_ = "TestAdminAbility",
            .entInfo_ = entInfo, .permission_ = permissions,
            .adminType_ = static_cast<AdminType>(adminType), .isDebug_ = isDebug };
        AdminContainer::GetInstance()->SetAdminByUserId(userId, adminInfo);
    }
};

/**
 * @tc.name: GetInstance_001
 * @tc.desc: Verify GetInstance returns non-null singleton.
 * @tc.type: FUNC
 */
HWTEST_F(RestoreExtensionHandlerTest, GetInstance_001, TestSize.Level1)
{
    auto* instance = RestoreExtensionHandler::GetInstance();
    ASSERT_NE(instance, nullptr);
    ASSERT_EQ(instance, RestoreExtensionHandler::GetInstance());
}

/**
 * @tc.name: OnRestore_DeviceReject_001
 * @tc.desc: OnRestore rejects before reading payload when device validation fails:
 *           non-pc build reports INTERFACE_UNSUPPORTED; pc build on a non-enterprise
 *           device reports NOT_ENTERPRISE_DEVICE. On an enterprise device the payload is
 *           handed to the real AP verify path, so only "not rejected by device check" is
 *           asserted (the UT device has the real AP installed).
 * @tc.type: FUNC
 */
HWTEST_F(RestoreExtensionHandlerTest, OnRestore_DeviceReject_001, TestSize.Level1)
{
    int32_t fd = PipeWithContent(R"({"version":1,"admins":[]})");
    ASSERT_GE(fd, 0);
    MessageParcel data;
    ASSERT_TRUE(data.WriteFileDescriptor(fd));
    close(fd);
    ASSERT_TRUE(data.WriteString("restoreInfo"));

    MessageParcel reply;
    ErrCode ret = RestoreExtensionHandler::GetInstance()->OnRestore(data, reply);
    ASSERT_EQ(ret, ERR_OK);
    std::string resultJson = reply.ReadString();
    ASSERT_FALSE(resultJson.empty());
    cJSON *root = cJSON_Parse(resultJson.c_str());
    ASSERT_NE(root, nullptr);
    cJSON *resultInfo = cJSON_GetObjectItem(root, "resultInfo");
    ASSERT_TRUE(cJSON_IsArray(resultInfo));
    ASSERT_EQ(cJSON_GetArraySize(resultInfo), 1);
    cJSON *errorObj = cJSON_GetArrayItem(resultInfo, 0);
    ASSERT_NE(errorObj, nullptr);
    cJSON *type = cJSON_GetObjectItem(errorObj, "type");
    ASSERT_TRUE(cJSON_IsString(type));
    ASSERT_STREQ(type->valuestring, "ErrorInfo");
    cJSON *errorCode = cJSON_GetObjectItem(errorObj, "errorCode");
    ASSERT_TRUE(cJSON_IsString(errorCode));
#ifdef FEATURE_PC_ONLY
    if (!RestoreExtensionHandler::GetInstance()->IsEnterpriseDevice()) {
        ASSERT_STREQ(errorCode->valuestring, "9200018");
    } else {
        ASSERT_STRNE(errorCode->valuestring, "9200018");
    }
#else
    ASSERT_STREQ(errorCode->valuestring, "801");
#endif
    cJSON_Delete(root);
}

/**
 * @tc.name: ReadAndVerify_InvalidFd_001
 * @tc.desc: ReadAndVerify reports PARAM_ERROR for an invalid fd before any verify call.
 * @tc.type: FUNC
 */
HWTEST_F(RestoreExtensionHandlerTest, ReadAndVerify_InvalidFd_001, TestSize.Level1)
{
    std::vector<AdminBackupItem> admins;
    RestoreSummary summary;
    bool ok = RestoreExtensionHandler::GetInstance()->ReadAndVerify(-1, admins, summary);
    ASSERT_FALSE(ok);
    ASSERT_TRUE(admins.empty());
    ASSERT_EQ(summary.errorCode, static_cast<int32_t>(EdmReturnErrCode::PARAM_ERROR));
}

/**
 * @tc.name: CheckExistingAdmin_NotExist_001
 * @tc.desc: CheckExistingAdmin returns false when the admin is not enabled yet,
 *           so the caller continues with capacity checks and enable flow.
 * @tc.type: FUNC
 */
HWTEST_F(RestoreExtensionHandlerTest, CheckExistingAdmin_NotExist_001, TestSize.Level1)
{
    AdminBackupItem item;
    item.bundleName = "com.test.not.enabled";
    item.abilityName = "TestAdminAbility";
    item.userId = 100;
    item.adminType = static_cast<int32_t>(AdminType::NORMAL);
    RestoreItem outResult;
    bool exists = RestoreExtensionHandler::GetInstance()->CheckExistingAdmin(item, outResult);
    ASSERT_FALSE(exists);
    ASSERT_EQ(outResult.bundleName, item.bundleName);
    ASSERT_TRUE(outResult.result.empty());
}

/**
 * @tc.name: EnableAdminFromBackup_PrecheckReject_001
 * @tc.desc: EnableAdminFromBackup rejects an illegal admin type at EnableAdminPreCheck
 *           with PARAM_ERROR before touching bundle manager or storage.
 * @tc.type: FUNC
 */
HWTEST_F(RestoreExtensionHandlerTest, EnableAdminFromBackup_PrecheckReject_001, TestSize.Level1)
{
    AdminBackupItem item;
    item.bundleName = "com.test.admin";
    item.abilityName = "TestAdminAbility";
    item.userId = 100;
    item.adminType = 999;
    item.enableSource = 0;
    item.isDebug = false;
    ErrCode ret = RestoreExtensionHandler::GetInstance()->EnableAdminFromBackup(item);
    ASSERT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::PARAM_ERROR));
}

/**
 * @tc.name: EnableAdminFromBackup_VerifyConditionReject_001
 * @tc.desc: EnableAdminFromBackup rejects an ENT admin restored to a non-default user:
 *           VerifyEnableAdminCondition fails and the error maps to ENABLE_ADMIN_FAILED,
 *           matching the regular EnableAdminWithPermission behavior.
 * @tc.type: FUNC
 */
HWTEST_F(RestoreExtensionHandlerTest, EnableAdminFromBackup_VerifyConditionReject_001, TestSize.Level1)
{
    AdminBackupItem item;
    item.bundleName = "com.test.admin";
    item.abilityName = "TestAdminAbility";
    item.userId = EdmConstants::DEFAULT_USER_ID + 1; // ENT 仅允许激活到默认用户
    item.adminType = static_cast<int32_t>(AdminType::ENT);
    item.enableSource = 0;
    item.isDebug = false;
    ErrCode ret = RestoreExtensionHandler::GetInstance()->EnableAdminFromBackup(item);
    ASSERT_EQ(ret, static_cast<int32_t>(EdmReturnErrCode::ENABLE_ADMIN_FAILED));
}

/**
 * @tc.name: CheckExistingAdmin_ExistsSuccess_001
 * @tc.desc: CheckExistingAdmin reports SUCCESS for an admin already enabled with the
 *           same type and debug flag (idempotent restore skip).
 * @tc.type: FUNC
 */
HWTEST_F(RestoreExtensionHandlerTest, CheckExistingAdmin_ExistsSuccess_001, TestSize.Level1)
{
    const std::string bundleName = "com.test.already.enabled";
    SeedAdmin(bundleName, EdmConstants::DEFAULT_USER_ID, static_cast<int32_t>(AdminType::NORMAL), false);

    AdminBackupItem item;
    item.bundleName = bundleName;
    item.abilityName = "TestAdminAbility";
    item.userId = EdmConstants::DEFAULT_USER_ID;
    item.adminType = static_cast<int32_t>(AdminType::NORMAL);
    item.isDebug = false;
    RestoreItem outResult;
    bool handled = RestoreExtensionHandler::GetInstance()->CheckExistingAdmin(item, outResult);
    AdminContainer::GetInstance()->DeleteAdmin(bundleName, EdmConstants::DEFAULT_USER_ID);

    ASSERT_TRUE(handled);
    ASSERT_EQ(outResult.result, "SUCCESS");
    ASSERT_EQ(outResult.errorCode, 0);
    ASSERT_TRUE(outResult.idempotent); // 幂等命中计入 CountInfo.duplicateCount
}

/**
 * @tc.name: CheckExistingAdmin_SameTypeIdempotent_001
 * @tc.desc: CheckExistingAdmin treats an enabled admin with the same type as idempotent
 *           success even when the debug flag differs from the backup record, per design
 *           Step6 (一致性仅比对激活类型，不改变状态).
 * @tc.type: FUNC
 */
HWTEST_F(RestoreExtensionHandlerTest, CheckExistingAdmin_SameTypeIdempotent_001, TestSize.Level1)
{
    const std::string bundleName = "com.test.debug.mismatch";
    SeedAdmin(bundleName, EdmConstants::DEFAULT_USER_ID, static_cast<int32_t>(AdminType::NORMAL), false);

    AdminBackupItem item;
    item.bundleName = bundleName;
    item.abilityName = "TestAdminAbility";
    item.userId = EdmConstants::DEFAULT_USER_ID;
    item.adminType = static_cast<int32_t>(AdminType::NORMAL);
    item.isDebug = true;
    RestoreItem outResult;
    bool handled = RestoreExtensionHandler::GetInstance()->CheckExistingAdmin(item, outResult);
    AdminContainer::GetInstance()->DeleteAdmin(bundleName, EdmConstants::DEFAULT_USER_ID);

    ASSERT_TRUE(handled);
    ASSERT_EQ(outResult.result, "SUCCESS");
    ASSERT_EQ(outResult.errorCode, 0);
    ASSERT_TRUE(outResult.idempotent);
}

} // namespace EDM
} // namespace OHOS

