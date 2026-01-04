/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef EDM_UNIT_TEST_PLUGIN_MANAGER_TEST_H
#define EDM_UNIT_TEST_PLUGIN_MANAGER_TEST_H

#include <gtest/gtest.h>
#include <iremote_object.h>
#include "edm_log.h"
#define private public
#define protected public
#include "iplugin.h"
#undef private
#undef protected

namespace OHOS {
namespace EDM {
namespace TEST {
class TestPlugin : public IPlugin {
public:
    TestPlugin()
    {
        policyCode_ = 0;
        policyName_ = "TestPlugin";
        permissionConfig_.typePermissions[IPlugin::PermissionType::NORMAL_DEVICE_ADMIN] =
            "ohos.permission.EDM_TEST_PERMISSION";
        permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
        EDMLOGD("TestPlugin constructor");
    }

    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override
    {
        return ERR_OK;
    }

    ErrCode GetOthersMergePolicyData(const std::string &adminName, int32_t userId, std::string &policyData) override
    {
        return IPlugin::GetOthersMergePolicyData(adminName, userId, policyData);
    }

    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override {}

    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData, const std::string &mergeData,
        int32_t userId) override
    {
        return ERR_OK;
    }

    void OnAdminRemoveDone(const std::string &adminName, const std::string &policyData, int32_t userId) override {}

    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId)
    {
        return ERR_OK;
    }

    void OnOtherServiceStart(int32_t systemAbilityId) override
    {
        callOnOtherServiceStartFlag_ = true;
    }

    void OnOtherServiceStartForAdmin(const std::string &adminName, int32_t userId) override
    {
        callOnOtherServiceStartForAdminFlag_ = true;
    }

    ~TestPlugin() override = default;

    bool callOnOtherServiceStartFlag_ = false;

    bool callOnOtherServiceStartForAdminFlag_ = false;
};

class TestExtensionPlugin : public IPlugin {
public:
    TestExtensionPlugin()
    {
        policyCode_ = 1;
        policyName_ = "TestExtensionPlugin";
        permissionConfig_.typePermissions.clear();
        permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN,
            "ohos.permission.EDM_TEST_PERMISSION");
        permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
        EDMLOGD("TestExtensionPlugin constructor");
    }

    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override
    {
        return ERR_OK;
    }

    ErrCode GetOthersMergePolicyData(const std::string &adminName, int32_t userId, std::string &policyData) override
    {
        return IPlugin::GetOthersMergePolicyData(adminName, userId, policyData);
    }

    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override {}

    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData, const std::string &mergeData,
        int32_t userId) override
    {
        return ERR_OK;
    }

    void OnAdminRemoveDone(const std::string &adminName, const std::string &policyData, int32_t userId) override {}

    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId)
    {
        return ERR_OK;
    }

    ~TestExtensionPlugin() override = default;
};

class PluginManagerTest : public testing::Test {
protected:
    virtual void SetUp() override;

    virtual void TearDown() override;
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_PLUGIN_MANAGER_TEST_H
