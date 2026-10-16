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

#include "get_shared_path_list_plugin.h"

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "iplugin.h"
#include "message_parcel.h"
#include "shared_path_info.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class GetSharedPathListPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void GetSharedPathListPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void GetSharedPathListPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

HWTEST_F(GetSharedPathListPluginTest, TestOnHandlePolicy, TestSize.Level1)
{
    GetSharedPathListPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    int32_t userId = 0;

    ErrCode ret = plugin.OnHandlePolicy(EdmInterfaceCode::GET_SHARED_PATH_LIST, data, reply, policyData, userId);
    ASSERT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

HWTEST_F(GetSharedPathListPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    GetSharedPathListPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    int32_t userId = 0;

    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

HWTEST_F(GetSharedPathListPluginTest, TestPluginCode, TestSize.Level1)
{
    GetSharedPathListPlugin plugin;
    ASSERT_EQ(plugin.GetCode(), EdmInterfaceCode::GET_SHARED_PATH_LIST);
}

HWTEST_F(GetSharedPathListPluginTest, TestPluginName, TestSize.Level1)
{
    GetSharedPathListPlugin plugin;
    ASSERT_EQ(plugin.GetPolicyName(), PolicyName::POLICY_GET_SHARED_PATH_LIST);
}

HWTEST_F(GetSharedPathListPluginTest, TestOnAdminRemove, TestSize.Level1)
{
    GetSharedPathListPlugin plugin;
    std::string adminName = "test_admin";
    std::string policyData = "{}";
    std::string mergeJsonData = "{}";
    int32_t userId = 0;

    ErrCode ret = plugin.OnAdminRemove(adminName, policyData, mergeJsonData, userId);
    ASSERT_EQ(ret, ERR_OK);
}

HWTEST_F(GetSharedPathListPluginTest, TestPathSharedDataMarshalling, TestSize.Level1)
{
    PathSharedData data;
    data.shareName = "share_test";
    data.shareUri = "file:///data/service/share_test";
    data.shareLimit = 5;
    UserPathInfo user1;
    user1.userName = "user1";
    user1.userPermission = "readonly";
    UserPathInfo user2;
    user2.userName = "user2";
    user2.userPermission = "readwrite";
    data.userPathInfoList = {user1, user2};

    MessageParcel parcel;
    ASSERT_TRUE(data.Marshalling(parcel));

    PathSharedData result = PathSharedData::Unmarshalling(parcel);
    ASSERT_EQ(result.shareName, "share_test");
    ASSERT_EQ(result.shareUri, "file:///data/service/share_test");
    ASSERT_EQ(result.shareLimit, 5);
    ASSERT_EQ(result.userPathInfoList.size(), 2u);
    ASSERT_EQ(result.userPathInfoList[0].userName, "user1");
    ASSERT_EQ(result.userPathInfoList[0].userPermission, "readonly");
    ASSERT_EQ(result.userPathInfoList[1].userName, "user2");
    ASSERT_EQ(result.userPathInfoList[1].userPermission, "readwrite");
}

HWTEST_F(GetSharedPathListPluginTest, TestPathSharedDataEmptyList, TestSize.Level1)
{
    PathSharedData data;
    data.shareName = "empty_share";
    data.shareUri = "file:///data/empty";
    data.shareLimit = 0;

    MessageParcel parcel;
    ASSERT_TRUE(data.Marshalling(parcel));

    PathSharedData result = PathSharedData::Unmarshalling(parcel);
    ASSERT_EQ(result.shareName, "empty_share");
    ASSERT_EQ(result.shareUri, "file:///data/empty");
    ASSERT_EQ(result.shareLimit, 0);
    ASSERT_TRUE(result.userPathInfoList.empty());
}

HWTEST_F(GetSharedPathListPluginTest, TestPathSharedDataOverLimit, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteString("over_limit_share");
    parcel.WriteString("file:///data/overlimit");
    parcel.WriteUint32(SHARED_PATH_MAX_COUNT + 1);
    parcel.WriteInt32(10);

    PathSharedData result = PathSharedData::Unmarshalling(parcel);
    ASSERT_EQ(result.shareName, "over_limit_share");
    ASSERT_EQ(result.shareUri, "file:///data/overlimit");
    ASSERT_EQ(result.shareLimit, 0);
    ASSERT_TRUE(result.userPathInfoList.empty());
}

HWTEST_F(GetSharedPathListPluginTest, TestUserPathInfoMarshalling, TestSize.Level1)
{
    UserPathInfo info;
    info.userName = "admin_user";
    info.userPermission = "full_control";

    MessageParcel parcel;
    ASSERT_TRUE(info.Marshalling(parcel));

    UserPathInfo result = UserPathInfo::Unmarshalling(parcel);
    ASSERT_EQ(result.userName, "admin_user");
    ASSERT_EQ(result.userPermission, "full_control");
}

HWTEST_F(GetSharedPathListPluginTest, TestUserPathInfoEmptyFields, TestSize.Level1)
{
    UserPathInfo info;
    info.userName = "";
    info.userPermission = "";

    MessageParcel parcel;
    ASSERT_TRUE(info.Marshalling(parcel));

    UserPathInfo result = UserPathInfo::Unmarshalling(parcel);
    ASSERT_TRUE(result.userName.empty());
    ASSERT_TRUE(result.userPermission.empty());
}

HWTEST_F(GetSharedPathListPluginTest, TestPathSharedDataSingleElement, TestSize.Level1)
{
    PathSharedData data;
    data.shareName = "single_share";
    data.shareUri = "file:///data/single";
    data.shareLimit = 1;
    UserPathInfo user;
    user.userName = "only_user";
    user.userPermission = "readonly";
    data.userPathInfoList = {user};

    MessageParcel parcel;
    ASSERT_TRUE(data.Marshalling(parcel));

    PathSharedData result = PathSharedData::Unmarshalling(parcel);
    ASSERT_EQ(result.shareName, "single_share");
    ASSERT_EQ(result.shareUri, "file:///data/single");
    ASSERT_EQ(result.shareLimit, 1);
    ASSERT_EQ(result.userPathInfoList.size(), 1u);
    ASSERT_EQ(result.userPathInfoList[0].userName, "only_user");
    ASSERT_EQ(result.userPathInfoList[0].userPermission, "readonly");
}

HWTEST_F(GetSharedPathListPluginTest, TestPathSharedDataDefaultShareLimit, TestSize.Level1)
{
    PathSharedData data;
    ASSERT_EQ(data.shareLimit, 0);

    MessageParcel parcel;
    ASSERT_TRUE(data.Marshalling(parcel));

    PathSharedData result = PathSharedData::Unmarshalling(parcel);
    ASSERT_EQ(result.shareLimit, 0);
}

HWTEST_F(GetSharedPathListPluginTest, TestPathSharedDataNegativeShareLimit, TestSize.Level1)
{
    PathSharedData data;
    data.shareName = "neg_limit";
    data.shareUri = "file:///data/neg";
    data.shareLimit = -1;

    MessageParcel parcel;
    ASSERT_TRUE(data.Marshalling(parcel));

    PathSharedData result = PathSharedData::Unmarshalling(parcel);
    ASSERT_EQ(result.shareLimit, -1);
}

HWTEST_F(GetSharedPathListPluginTest, TestPathSharedDataExactlyMaxCount, TestSize.Level1)
{
    PathSharedData data;
    data.shareName = "max_share";
    data.shareUri = "file:///data/max";
    data.shareLimit = 100;
    for (uint32_t i = 0; i < SHARED_PATH_MAX_COUNT; ++i) {
        UserPathInfo user;
        user.userName = "user" + std::to_string(i);
        user.userPermission = "readonly";
        data.userPathInfoList.push_back(user);
    }

    MessageParcel parcel;
    ASSERT_TRUE(data.Marshalling(parcel));

    PathSharedData result = PathSharedData::Unmarshalling(parcel);
    ASSERT_EQ(result.shareName, "max_share");
    ASSERT_EQ(result.userPathInfoList.size(), SHARED_PATH_MAX_COUNT);
    ASSERT_EQ(result.userPathInfoList[0].userName, "user0");
}

HWTEST_F(GetSharedPathListPluginTest, TestPluginNeedSavePolicy, TestSize.Level1)
{
    GetSharedPathListPlugin plugin;
    ASSERT_FALSE(plugin.NeedSavePolicy());
}

HWTEST_F(GetSharedPathListPluginTest, TestPluginPermission, TestSize.Level1)
{
    GetSharedPathListPlugin plugin;
    ASSERT_EQ(plugin.GetPermission(FuncOperateType::GET, IPlugin::PermissionType::SUPER_DEVICE_ADMIN),
        "ohos.permission.ENTERPRISE_MANAGE_NETWORK");
    ASSERT_EQ(plugin.GetPermission(FuncOperateType::SET, IPlugin::PermissionType::SUPER_DEVICE_ADMIN),
        "ohos.permission.ENTERPRISE_MANAGE_NETWORK");
    ASSERT_EQ(plugin.GetPermission(FuncOperateType::REMOVE, IPlugin::PermissionType::SUPER_DEVICE_ADMIN),
        "ohos.permission.ENTERPRISE_MANAGE_NETWORK");
}

HWTEST_F(GetSharedPathListPluginTest, TestPluginApiType, TestSize.Level1)
{
    GetSharedPathListPlugin plugin;
    ASSERT_EQ(plugin.GetApiType(FuncOperateType::GET), IPlugin::ApiType::PUBLIC);
    ASSERT_EQ(plugin.GetApiType(FuncOperateType::SET), IPlugin::ApiType::PUBLIC);
}

HWTEST_F(GetSharedPathListPluginTest, TestOnHandlePolicyDone, TestSize.Level1)
{
    GetSharedPathListPlugin plugin;
    std::string adminName = "test_admin";
    bool isGlobalChanged = false;
    int32_t userId = 0;
    plugin.OnHandlePolicyDone(EdmInterfaceCode::GET_SHARED_PATH_LIST, adminName, isGlobalChanged, userId);
    SUCCEED();
}

HWTEST_F(GetSharedPathListPluginTest, TestOnAdminRemoveDone, TestSize.Level1)
{
    GetSharedPathListPlugin plugin;
    std::string adminName = "test_admin";
    std::string currentJsonData = "{}";
    int32_t userId = 0;
    plugin.OnAdminRemoveDone(adminName, currentJsonData, userId);
    SUCCEED();
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
