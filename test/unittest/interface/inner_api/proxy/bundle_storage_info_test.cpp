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

#include "bundle_storage_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t TEST_APP_SIZE = 1024;
const int32_t TEST_DATA_SIZE = 2048;
class BundleStorageInfoTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}
};

/**
 * @tc.name: BundleStorageInfoMarshalling001
 * @tc.desc: Test BundleStorageInfo Marshalling success
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoMarshalling001, TestSize.Level1)
{
    BundleStorageInfo info;
    info.bundleName = "com.test.app";
    info.appSize = TEST_APP_SIZE;
    info.dataSize = TEST_DATA_SIZE;

    MessageParcel parcel;
    bool ret = info.Marshalling(parcel);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: BundleStorageInfoReadFromParcel001
 * @tc.desc: Test BundleStorageInfo ReadFromParcel success
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoReadFromParcel001, TestSize.Level1)
{
    BundleStorageInfo writeInfo;
    writeInfo.bundleName = "com.test.app";
    writeInfo.appSize = TEST_APP_SIZE;
    writeInfo.dataSize = TEST_DATA_SIZE;

    MessageParcel parcel;
    bool ret = writeInfo.Marshalling(parcel);
    ASSERT_TRUE(ret);

    BundleStorageInfo readInfo;
    ret = readInfo.ReadFromParcel(parcel);
    ASSERT_TRUE(ret);
    ASSERT_EQ(readInfo.bundleName, "com.test.app");
    ASSERT_EQ(readInfo.appSize, TEST_APP_SIZE);
    ASSERT_EQ(readInfo.dataSize, TEST_DATA_SIZE);
}

/**
 * @tc.name: BundleStorageInfoUnmarshalling001
 * @tc.desc: Test BundleStorageInfo Unmarshalling success
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoUnmarshalling001, TestSize.Level1)
{
    BundleStorageInfo writeInfo;
    writeInfo.bundleName = "com.test.app";
    writeInfo.appSize = TEST_APP_SIZE;
    writeInfo.dataSize = TEST_DATA_SIZE;

    MessageParcel parcel;
    bool ret = writeInfo.Marshalling(parcel);
    ASSERT_TRUE(ret);

    BundleStorageInfo *readInfo = BundleStorageInfo::Unmarshalling(parcel);
    ASSERT_NE(readInfo, nullptr);
    ASSERT_EQ(readInfo->bundleName, "com.test.app");
    ASSERT_EQ(readInfo->appSize, TEST_APP_SIZE);
    ASSERT_EQ(readInfo->dataSize, TEST_DATA_SIZE);
    delete readInfo;
}

/**
 * @tc.name: BundleStorageInfoUnmarshalling002
 * @tc.desc: Test BundleStorageInfo Unmarshalling with empty bundleName
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoUnmarshalling002, TestSize.Level1)
{
    BundleStorageInfo writeInfo;
    writeInfo.bundleName = "";
    writeInfo.appSize = 0;
    writeInfo.dataSize = 0;

    MessageParcel parcel;
    bool ret = writeInfo.Marshalling(parcel);
    ASSERT_TRUE(ret);

    BundleStorageInfo *readInfo = BundleStorageInfo::Unmarshalling(parcel);
    ASSERT_NE(readInfo, nullptr);
    ASSERT_EQ(readInfo->bundleName, "");
    ASSERT_EQ(readInfo->appSize, 0);
    ASSERT_EQ(readInfo->dataSize, 0);
    delete readInfo;
}

/**
 * @tc.name: BundleStorageInfoMarshalling002
 * @tc.desc: Test BundleStorageInfo Marshalling with large values
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoMarshalling002, TestSize.Level1)
{
    BundleStorageInfo info;
    info.bundleName = "com.test.large.app";
    info.appSize = INT64_MAX;
    info.dataSize = INT64_MAX;

    MessageParcel parcel;
    bool ret = info.Marshalling(parcel);
    ASSERT_TRUE(ret);

    BundleStorageInfo *readInfo = BundleStorageInfo::Unmarshalling(parcel);
    ASSERT_NE(readInfo, nullptr);
    ASSERT_EQ(readInfo->bundleName, "com.test.large.app");
    ASSERT_EQ(readInfo->appSize, INT64_MAX);
    ASSERT_EQ(readInfo->dataSize, INT64_MAX);
    delete readInfo;
}

/**
 * @tc.name: BundleStorageInfoMarshalling003
 * @tc.desc: Test BundleStorageInfo Marshalling with negative values
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoMarshalling003, TestSize.Level1)
{
    BundleStorageInfo info;
    info.bundleName = "com.test.negative.app";
    info.appSize = -1;
    info.dataSize = -1;

    MessageParcel parcel;
    bool ret = info.Marshalling(parcel);
    ASSERT_TRUE(ret);

    BundleStorageInfo *readInfo = BundleStorageInfo::Unmarshalling(parcel);
    ASSERT_NE(readInfo, nullptr);
    ASSERT_EQ(readInfo->bundleName, "com.test.negative.app");
    ASSERT_EQ(readInfo->appSize, -1);
    ASSERT_EQ(readInfo->dataSize, -1);
    delete readInfo;
}

/**
 * @tc.name: BundleStorageInfoUnmarshalling003
 * @tc.desc: Test BundleStorageInfo Unmarshalling with unicode bundleName
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoUnmarshalling003, TestSize.Level1)
{
    BundleStorageInfo writeInfo;
    writeInfo.bundleName = "com.test.app";
    writeInfo.appSize = TEST_APP_SIZE;
    writeInfo.dataSize = TEST_DATA_SIZE;

    MessageParcel parcel;
    bool ret = writeInfo.Marshalling(parcel);
    ASSERT_TRUE(ret);

    BundleStorageInfo *readInfo = BundleStorageInfo::Unmarshalling(parcel);
    ASSERT_NE(readInfo, nullptr);
    ASSERT_EQ(readInfo->bundleName, "com.test.app");
    ASSERT_EQ(readInfo->appSize, TEST_APP_SIZE);
    ASSERT_EQ(readInfo->dataSize, TEST_DATA_SIZE);
    delete readInfo;
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
