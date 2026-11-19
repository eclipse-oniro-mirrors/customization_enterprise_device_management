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

#include <string>

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
    ASSERT_EQ(ret, ERR_OK);
    int32_t replyCode = ERR_OK;
    ASSERT_TRUE(reply.ReadInt32(replyCode));
    ASSERT_EQ(replyCode, ERR_OK);

    uint32_t size = 1;
    ASSERT_TRUE(reply.ReadUint32(size));
    ASSERT_EQ(size, 0u);
}

HWTEST_F(GetSharedPathListPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    GetSharedPathListPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    int32_t userId = 0;

    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_EQ(ret, ERR_OK);

    int32_t replyCode = ERR_OK;
    ASSERT_TRUE(reply.ReadInt32(replyCode));
    ASSERT_EQ(replyCode, ERR_OK);

    uint32_t size = 1;
    ASSERT_TRUE(reply.ReadUint32(size));
    ASSERT_EQ(size, 0u);
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

    MessageParcel parcel;
    ASSERT_TRUE(data.Marshalling(parcel));

    PathSharedData result = PathSharedData::Unmarshalling(parcel);
    ASSERT_EQ(result.shareName, "share_test");
    ASSERT_EQ(result.shareUri, "file:///data/service/share_test");
}

HWTEST_F(GetSharedPathListPluginTest, TestPathSharedDataEmptyList, TestSize.Level1)
{
    PathSharedData data;
    data.shareName = "empty_share";
    data.shareUri = "file:///data/empty";

    MessageParcel parcel;
    ASSERT_TRUE(data.Marshalling(parcel));

    PathSharedData result = PathSharedData::Unmarshalling(parcel);
    ASSERT_EQ(result.shareName, "empty_share");
    ASSERT_EQ(result.shareUri, "file:///data/empty");
}

HWTEST_F(GetSharedPathListPluginTest, TestPathSharedDataParcelOrder, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteString("admin_user");
    parcel.WriteString("full_control");

    std::string userName = parcel.ReadString();
    std::string userPermission = parcel.ReadString();
    ASSERT_EQ(userName, "admin_user");
    ASSERT_EQ(userPermission, "full_control");
}

HWTEST_F(GetSharedPathListPluginTest, TestPathSharedDataSingleElement, TestSize.Level1)
{
    PathSharedData data;
    data.shareName = "single_share";
    data.shareUri = "file:///data/single";

    MessageParcel parcel;
    ASSERT_TRUE(data.Marshalling(parcel));

    PathSharedData result = PathSharedData::Unmarshalling(parcel);
    ASSERT_EQ(result.shareName, "single_share");
    ASSERT_EQ(result.shareUri, "file:///data/single");
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
