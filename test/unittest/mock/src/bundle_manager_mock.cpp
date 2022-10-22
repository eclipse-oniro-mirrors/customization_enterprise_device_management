/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "gmock/gmock.h"
#include "bundle_manager_mock.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t ERR_FAIL_NAMEFORUID = 777;
}
bool BundleMgrProxy::QueryExtensionAbilityInfos(const Want &want, const ExtensionAbilityType &extensionType,
    const int32_t &flag, const int32_t &userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    GTEST_LOG_(INFO) << "mock BundleMgrProxy QueryExtensionAbilityInfos in";
    if (userId == 1) {
        GTEST_LOG_(INFO) << "mock BundleMgrProxy QueryExtensionAbilityInfos userId==1 return";
        return false;
    }
    ExtensionAbilityInfo extensionAbilityInfo;
    AppExecFwk::ElementName admin = want.GetElement();
    if (admin.GetBundleName() == "com.edm.test.demo22" ||
        admin.GetBundleName() == "com.edm.test.demo33") {
    } else {
        extensionAbilityInfo.bundleName = admin.GetBundleName();
        extensionAbilityInfo.name = admin.GetAbilityName();
    }
    extensionInfos.emplace_back(extensionAbilityInfo);
    GTEST_LOG_(INFO) << "mock BundleMgrProxy QueryExtensionAbilityInfos bundleName=" << admin.GetBundleName() <<
        " abilityName=" << admin.GetAbilityName();
    return true;
}

ErrCode BundleMgrProxy::GetNameForUid(const int uid, std::string &name)
{
    GTEST_LOG_(INFO) << "mock BundleMgrProxy GetNameForUid in bundleNameMock_=" << bundleNameMock_;
    if (bundleNameMock_ == "com.edm.test.demo.ipc.suc") {
        name = bundleNameMock_;
    } else if (bundleNameMock_ == "com.edm.test.demo.ipc.fail") {
        return ERR_FAIL_NAMEFORUID;
    }
    return ERR_OK;
}

bool BundleMgrProxy::GetBundleInfo(const std::string &bundleName, const BundleFlag flag,
    BundleInfo &bundleInfo, int32_t userId)
{
    GTEST_LOG_(INFO) << "mock BundleMgrProxy GetBundleInfo in";
    if (userId == 0) {
        GTEST_LOG_(INFO) << "mock BundleMgrProxy GetBundleInfo userId==0 return";
        return false;
    }
    if (bundleName == "com.edm.test.demo") {
        bundleInfo.reqPermissions.emplace_back("ohos.permission.aaa");
        bundleInfo.reqPermissions.emplace_back("ohos.permission.bbb");
        GTEST_LOG_(INFO) << "mock BundleMgrProxy com.edm.test.demo in";
    } else if (bundleName == "com.edm.test.demo.ipc.suc") {
        bundleInfo.reqPermissions.emplace_back("ohos.permission.aaa");
        bundleInfo.reqPermissions.emplace_back("ohos.permission.bbb");
        GTEST_LOG_(INFO) << "mock BundleMgrProxy com.edm.test.demo.ipc.suc in";
        bundleNameMock_ = bundleName;
    } else if (bundleName == "com.edm.test.demo.ipc.fail") {
        bundleInfo.reqPermissions.emplace_back("ohos.permission.aaa");
        bundleInfo.reqPermissions.emplace_back("ohos.permission.bbb");
        GTEST_LOG_(INFO) << "mock BundleMgrProxy com.edm.test.demo.ipc.fail in";
        bundleNameMock_ = bundleName;
    } else if (bundleName == "com.edm.test.permission.empty") {
    } else if (bundleName == "com.edm.test.demo11") {
        bundleInfo.reqPermissions.emplace_back("ohos.permission.EDM_TEST_PERMISSION");
        bundleInfo.reqPermissions.emplace_back("ohos.permission.EDM_TEST_ENT_PERMISSION");
        GTEST_LOG_(INFO) << "mock BundleMgrProxy com.edm.test.demo11 in";
    } else if ((bundleName == "com.edm.test.demo22")) {
        bundleInfo.reqPermissions.emplace_back("ohos.permission.aaa");
        bundleInfo.reqPermissions.emplace_back("ohos.permission.bbb");
        GTEST_LOG_(INFO) << "mock BundleMgrProxy com.edm.test.demo22 in";
    } else if ((bundleName == "com.edm.test.demo33")) {
        bundleInfo.reqPermissions.emplace_back("ohos.permission.EDM_TEST_PERMISSION");
        bundleInfo.reqPermissions.emplace_back("ohos.permission.EDM_TEST_ENT_PERMISSION");
        GTEST_LOG_(INFO) << "mock BundleMgrProxy com.edm.test.demo33 in";
    }
    return true;
}

int BundleMgrStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock BundleMgrStub OnRemoteRequest in";
    return 0;
}

BundleMgrService::BundleMgrService()
{
    GTEST_LOG_(INFO) << "mock BundleMgrService constructor";
}

bool BundleMgrService::QueryExtensionAbilityInfos(const Want &want, const ExtensionAbilityType &extensionType,
    const int32_t &flag, const int32_t &userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    GTEST_LOG_(INFO) << "mock BundleMgrService QueryExtensionAbilityInfos in";
    if (userId == 1) {
        GTEST_LOG_(INFO) << "mock BundleMgrService QueryExtensionAbilityInfos userId==1 return";
        return false;
    }
    ExtensionAbilityInfo extensionAbilityInfo;
    AppExecFwk::ElementName admin = want.GetElement();
    if (admin.GetBundleName() == "com.edm.test.demo22" ||
        admin.GetBundleName() == "com.edm.test.demo33") {
    } else {
        extensionAbilityInfo.bundleName = admin.GetBundleName();
        extensionAbilityInfo.name = admin.GetAbilityName();
    }
    extensionInfos.emplace_back(extensionAbilityInfo);
    GTEST_LOG_(INFO) << "mock BundleMgrService QueryExtensionAbilityInfos bundleName=" << admin.GetBundleName() <<
        " abilityName=" << admin.GetAbilityName();
    return true;
}

ErrCode BundleMgrService::GetNameForUid(const int uid, std::string &name)
{
    GTEST_LOG_(INFO) << "mock BundleMgrService GetNameForUid in bundleNameMock_=" << bundleNameMock_;
    if (bundleNameMock_ == "com.edm.test.demo.ipc.suc") {
        name = bundleNameMock_;
    } else if (bundleNameMock_ == "com.edm.test.demo.ipc.fail") {
        return ERR_FAIL_NAMEFORUID;
    }
    return ERR_OK;
}

bool BundleMgrService::GetBundleInfo(const std::string &bundleName, const BundleFlag flag,
    BundleInfo &bundleInfo, int32_t userId)
{
    GTEST_LOG_(INFO) << "mock BundleMgrService GetBundleInfo in";
    if (userId == 0) {
        GTEST_LOG_(INFO) << "mock BundleMgrService GetBundleInfo userId==0 return";
        return false;
    }
    if (bundleName == "com.edm.test.demo") {
        bundleInfo.reqPermissions.emplace_back("ohos.permission.aaa");
        bundleInfo.reqPermissions.emplace_back("ohos.permission.bbb");
        GTEST_LOG_(INFO) << "mock BundleMgrService com.edm.test.demo in";
    } else if (bundleName == "com.edm.test.demo.ipc.suc") {
        bundleInfo.reqPermissions.emplace_back("ohos.permission.aaa");
        bundleInfo.reqPermissions.emplace_back("ohos.permission.bbb");
        GTEST_LOG_(INFO) << "mock BundleMgrService com.edm.test.demo.ipc.suc in";
        bundleNameMock_ = bundleName;
    } else if (bundleName == "com.edm.test.demo.ipc.fail") {
        bundleInfo.reqPermissions.emplace_back("ohos.permission.aaa");
        bundleInfo.reqPermissions.emplace_back("ohos.permission.bbb");
        GTEST_LOG_(INFO) << "mock BundleMgrService com.edm.test.demo.ipc.fail in";
        bundleNameMock_ = bundleName;
    } else if (bundleName == "com.edm.test.permission.empty") {
    } else if (bundleName == "com.edm.test.demo11") {
        bundleInfo.reqPermissions.emplace_back("ohos.permission.EDM_TEST_PERMISSION");
        bundleInfo.reqPermissions.emplace_back("ohos.permission.EDM_TEST_ENT_PERMISSION");
        GTEST_LOG_(INFO) << "mock BundleMgrService com.edm.test.demo11 in";
    } else if ((bundleName == "com.edm.test.demo22")) {
        bundleInfo.reqPermissions.emplace_back("ohos.permission.aaa");
        bundleInfo.reqPermissions.emplace_back("ohos.permission.bbb");
        GTEST_LOG_(INFO) << "mock BundleMgrService com.edm.test.demo22 in";
    } else if ((bundleName == "com.edm.test.demo33")) {
        bundleInfo.reqPermissions.emplace_back("ohos.permission.EDM_TEST_PERMISSION");
        bundleInfo.reqPermissions.emplace_back("ohos.permission.EDM_TEST_ENT_PERMISSION");
        GTEST_LOG_(INFO) << "mock BundleMgrService com.edm.test.demo33 in";
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
