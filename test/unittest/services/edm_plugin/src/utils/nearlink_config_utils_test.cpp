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

#define private public
#define protected public
#include "nearlink_config_utils.h"
#undef private
#undef protected

#include <vector>

#include "cJSON.h"
#include "nearlink_protocol_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
const char *const DENY_LIST_KEY = "ProtocolDenyList";
const std::string TEST_USER_ID = "100";
const std::string TEST_OTHER_USER_ID = "101";
const std::string TEST_SSAP = "SSAP";
const std::string TEST_TRANSFER = "DATA_TRANSFER";

cJSON *CreateUserItem(const std::vector<std::string> &protocols)
{
    cJSON *userItem = cJSON_CreateArray();
    for (const auto &protocol : protocols) {
        cJSON_AddItemToArray(userItem, cJSON_CreateString(protocol.c_str()));
    }
    return userItem;
}

cJSON *CreateDenyList(const std::string &userId, const std::vector<std::string> &protocols)
{
    cJSON *denyList = cJSON_CreateObject();
    cJSON_AddItemToObject(denyList, userId.c_str(), CreateUserItem(protocols));
    return denyList;
}

cJSON *CreateRoot(const std::string &userId, const std::vector<std::string> &protocols)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, DENY_LIST_KEY, CreateDenyList(userId, protocols));
    return root;
}
}

class NearlinkConfigUtilsTest : public testing::Test {};

/**
 * @tc.name: TestIsProtocolExist
 * @tc.desc: Test NearlinkConfigUtils::IsProtocolExist scans the user array only for strings.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestIsProtocolExist, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    cJSON *userItem = CreateUserItem({ TEST_SSAP, TEST_TRANSFER });
    EXPECT_TRUE(utils.IsProtocolExist(TEST_SSAP, userItem));
    EXPECT_TRUE(utils.IsProtocolExist(TEST_TRANSFER, userItem));
    EXPECT_FALSE(utils.IsProtocolExist("UNKNOWN", userItem));
    cJSON_Delete(userItem);
}

/**
 * @tc.name: TestIsProtocolExistEmptyItem
 * @tc.desc: Test NearlinkConfigUtils::IsProtocolExist returns false for an empty array.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestIsProtocolExistEmptyItem, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    cJSON *userItem = CreateUserItem({});
    EXPECT_FALSE(utils.IsProtocolExist(TEST_SSAP, userItem));
    cJSON_Delete(userItem);
}

/**
 * @tc.name: TestAddProtocolAlreadyExists
 * @tc.desc: Test AddProtocol reports success without touching an existing entry.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestAddProtocolAlreadyExists, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    cJSON *denyList = CreateDenyList(TEST_USER_ID, { TEST_SSAP });
    cJSON *userItem = cJSON_GetObjectItem(denyList, TEST_USER_ID.c_str());
    ASSERT_NE(userItem, nullptr);
    EXPECT_TRUE(utils.AddProtocol(TEST_SSAP, TEST_USER_ID, denyList, userItem));
    EXPECT_EQ(cJSON_GetArraySize(userItem), 1);
    cJSON_Delete(denyList);
}

/**
 * @tc.name: TestAddProtocolCreatesUserEntry
 * @tc.desc: Test AddProtocol creates the user array when the user has no entry yet.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestAddProtocolCreatesUserEntry, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    cJSON *denyList = cJSON_CreateObject();
    utils.AddProtocol(TEST_SSAP, TEST_USER_ID, denyList, nullptr);
    cJSON *userItem = cJSON_GetObjectItem(denyList, TEST_USER_ID.c_str());
    ASSERT_NE(userItem, nullptr);
    EXPECT_EQ(cJSON_GetArraySize(userItem), 1);
    EXPECT_TRUE(utils.IsProtocolExist(TEST_SSAP, userItem));
    cJSON_Delete(denyList);
}

/**
 * @tc.name: TestAddProtocolAppendsToExistingUser
 * @tc.desc: Test AddProtocol appends a second protocol to the same user entry.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestAddProtocolAppendsToExistingUser, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    cJSON *denyList = CreateDenyList(TEST_USER_ID, { TEST_SSAP });
    cJSON *userItem = cJSON_GetObjectItem(denyList, TEST_USER_ID.c_str());
    utils.AddProtocol(TEST_TRANSFER, TEST_USER_ID, denyList, userItem);
    EXPECT_EQ(cJSON_GetArraySize(userItem), 2);
    EXPECT_TRUE(utils.IsProtocolExist(TEST_TRANSFER, userItem));
    cJSON_Delete(denyList);
}

/**
 * @tc.name: TestRemoveProtocolWithoutUserItem
 * @tc.desc: Test RemoveProtocol succeeds when the user has no entry at all.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestRemoveProtocolWithoutUserItem, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    cJSON *denyList = cJSON_CreateObject();
    EXPECT_TRUE(utils.RemoveProtocol(TEST_SSAP, TEST_USER_ID, denyList, nullptr));
    cJSON_Delete(denyList);
}

/**
 * @tc.name: TestRemoveProtocolNotFound
 * @tc.desc: Test RemoveProtocol succeeds and keeps the entry when the protocol is absent.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestRemoveProtocolNotFound, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    cJSON *denyList = CreateDenyList(TEST_USER_ID, { TEST_SSAP });
    cJSON *userItem = cJSON_GetObjectItem(denyList, TEST_USER_ID.c_str());
    EXPECT_TRUE(utils.RemoveProtocol(TEST_TRANSFER, TEST_USER_ID, denyList, userItem));
    EXPECT_EQ(cJSON_GetArraySize(userItem), 1);
    cJSON_Delete(denyList);
}

/**
 * @tc.name: TestRemoveLastProtocolDropsUserEntry
 * @tc.desc: Test RemoveProtocol deletes the whole user entry once its last protocol goes.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestRemoveLastProtocolDropsUserEntry, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    cJSON *denyList = CreateDenyList(TEST_USER_ID, { TEST_SSAP });
    cJSON *userItem = cJSON_GetObjectItem(denyList, TEST_USER_ID.c_str());
    utils.RemoveProtocol(TEST_SSAP, TEST_USER_ID, denyList, userItem);
    EXPECT_EQ(cJSON_GetObjectItem(denyList, TEST_USER_ID.c_str()), nullptr);
    cJSON_Delete(denyList);
}

/**
 * @tc.name: TestQueryProtocolsKnownUser
 * @tc.desc: Test QueryProtocols converts every stored protocol name to its enum value.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestQueryProtocolsKnownUser, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    utils.root_ = CreateRoot(TEST_USER_ID, { TEST_SSAP, TEST_TRANSFER });
    std::vector<int32_t> protocols;
    EXPECT_TRUE(utils.QueryProtocols(TEST_USER_ID, protocols));
    ASSERT_EQ(protocols.size(), 2u);
    EXPECT_EQ(protocols[0], static_cast<int32_t>(NearlinkProtocol::SSAP));
    EXPECT_EQ(protocols[1], static_cast<int32_t>(NearlinkProtocol::DATA_TRANSFER));
}

/**
 * @tc.name: TestQueryProtocolsUnknownUser
 * @tc.desc: Test QueryProtocols returns an empty list for a user without an entry.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestQueryProtocolsUnknownUser, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    utils.root_ = CreateRoot(TEST_USER_ID, { TEST_SSAP });
    std::vector<int32_t> protocols;
    EXPECT_TRUE(utils.QueryProtocols(TEST_OTHER_USER_ID, protocols));
    EXPECT_TRUE(protocols.empty());
}

/**
 * @tc.name: TestQueryProtocolsWithoutDenyList
 * @tc.desc: Test QueryProtocols succeeds when the config holds no deny list.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestQueryProtocolsWithoutDenyList, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    utils.root_ = cJSON_CreateObject();
    std::vector<int32_t> protocols;
    EXPECT_TRUE(utils.QueryProtocols(TEST_USER_ID, protocols));
    EXPECT_TRUE(protocols.empty());
}

/**
 * @tc.name: TestCheckProtocolDenyListExists
 * @tc.desc: Test CheckProtocolDenyListExists creates the deny list only once.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestCheckProtocolDenyListExists, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    utils.root_ = cJSON_CreateObject();
    EXPECT_TRUE(utils.CheckProtocolDenyListExists());
    ASSERT_NE(cJSON_GetObjectItem(utils.root_, DENY_LIST_KEY), nullptr);
    EXPECT_TRUE(utils.CheckProtocolDenyListExists());
    EXPECT_EQ(cJSON_GetArraySize(cJSON_GetObjectItem(utils.root_, DENY_LIST_KEY)), 0);
}

/**
 * @tc.name: TestRemoveUserIdItem
 * @tc.desc: Test RemoveUserIdItem deletes the user entry from the injected config root.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestRemoveUserIdItem, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    utils.root_ = CreateRoot(TEST_USER_ID, { TEST_SSAP });
    utils.RemoveUserIdItem(TEST_USER_ID);
    cJSON *denyList = cJSON_GetObjectItem(utils.root_, DENY_LIST_KEY);
    ASSERT_NE(denyList, nullptr);
    EXPECT_EQ(cJSON_GetObjectItem(denyList, TEST_USER_ID.c_str()), nullptr);
}

/**
 * @tc.name: TestRemoveUserIdItemWithoutDenyList
 * @tc.desc: Test RemoveUserIdItem succeeds when no deny list is configured.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestRemoveUserIdItemWithoutDenyList, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    utils.root_ = cJSON_CreateObject();
    EXPECT_TRUE(utils.RemoveUserIdItem(TEST_USER_ID));
}

/**
 * @tc.name: TestUpdateProtocolAddsThenRemoves
 * @tc.desc: Test UpdateProtocol drives AddProtocol and RemoveProtocol through the config root.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestUpdateProtocolAddsThenRemoves, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    utils.root_ = cJSON_CreateObject();
    ASSERT_TRUE(utils.CheckProtocolDenyListExists());
    cJSON *denyList = cJSON_GetObjectItem(utils.root_, DENY_LIST_KEY);
    ASSERT_NE(denyList, nullptr);

    EXPECT_TRUE(utils.UpdateProtocol(TEST_USER_ID, TEST_SSAP, true));
    ASSERT_NE(cJSON_GetObjectItem(denyList, TEST_USER_ID.c_str()), nullptr);

    utils.UpdateProtocol(TEST_USER_ID, TEST_SSAP, false);
    EXPECT_EQ(cJSON_GetObjectItem(denyList, TEST_USER_ID.c_str()), nullptr);
}

/**
 * @tc.name: TestCreateNearlinkConfigDir
 * @tc.desc: Test CreateNearlinkConfigDir on an already existing directory.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkConfigUtilsTest, TestCreateNearlinkConfigDir, TestSize.Level1)
{
    NearlinkConfigUtils utils;
    EXPECT_TRUE(utils.CreateNearlinkConfigDir("/data/service/el1/public/edm/config/system/all"));
    EXPECT_FALSE(utils.CreateNearlinkConfigDir("/proc/forbidden-dir"));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
