/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef EDM_UNIT_TEST_IPLUGIN_TEMPLATE_TEST_H
#define EDM_UNIT_TEST_IPLUGIN_TEMPLATE_TEST_H

#include <gtest/gtest.h>

#include <map>
#include <string>
#include <vector>

#include "array_map_serializer.h"
#include "array_string_serializer.h"
#include "bool_serializer.h"
#include "func_code_utils.h"
#include "iplugin.h"
#include "json_serializer.h"
#include "map_string_serializer.h"
#include "plugin_manager.h"
#include "plugin_singleton.h"
#include "string_serializer.h"

namespace OHOS {
namespace EDM {
namespace TEST {
static bool g_visit = false;
namespace PLUGIN {
#ifndef ARRAY_TEST_PLUGIN
#define ARRAY_TEST_PLUGIN

class ArrayTestPlugin : public PluginSingleton<ArrayTestPlugin, std::vector<std::string>> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<ArrayTestPlugin, std::vector<std::string>>> ptr) override
    {
        int policyCode = 10;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "ArrayTestPlugin", config);
        ptr->SetSerializer(ArrayStringSerializer::GetInstance());
    }
};

#endif // ARRAY_TEST_PLUGIN

#ifndef BOOL_TEST_PLUGIN
#define BOOL_TEST_PLUGIN

class BoolTestPlugin : public PluginSingleton<BoolTestPlugin, bool> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<BoolTestPlugin, bool>> ptr) override
    {
        int policyCode = 11;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "BoolTestPlugin", config);
        ptr->SetSerializer(BoolSerializer::GetInstance());
    }
};

#endif // BOOL_TEST_PLUGIN

#ifndef MAP_TEST_PLUGIN
#define MAP_TEST_PLUGIN

class MapTestPlugin : public PluginSingleton<MapTestPlugin, std::map<std::string, std::string>> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<MapTestPlugin, std::map<std::string, std::string>>> ptr) override
    {
        int policyCode = 12;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "MapTestPlugin", config);
        ptr->SetSerializer(MapStringSerializer::GetInstance());
    }
};

#endif // MAP_TEST_PLUGIN

#ifndef ARRAY_MAP_TEST_PLUGIN
#define ARRAY_MAP_TEST_PLUGIN

class ArrayMapTestPlugin : public PluginSingleton<ArrayMapTestPlugin, std::vector<std::map<std::string, std::string>>> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<ArrayMapTestPlugin,
        std::vector<std::map<std::string, std::string>>>> ptr) override
    {
        int policyCode = 13;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "ArrayMapTestPlugin", config);
        ptr->SetSerializer(ArrayMapSerializer::GetInstance());
    }
};

#endif // ARRAY_MAP_TEST_PLUGIN

#ifndef JSON_TEST_PLUGIN
#define JSON_TEST_PLUGIN

class JsonTestPlugin : public PluginSingleton<JsonTestPlugin, Json::Value> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<JsonTestPlugin, Json::Value>> ptr) override
    {
        int policyCode = 14;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "JsonTestPlugin", config);
        ptr->SetSerializer(JsonSerializer::GetInstance());
    }
};

#endif // JSON_TEST_PLUGIN

#ifndef STRING_TEST_PLUGIN
#define STRING_TEST_PLUGIN

class StringTestPlugin : public PluginSingleton<StringTestPlugin, std::string> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<StringTestPlugin, std::string>> ptr) override
    {
        int policyCode = 15;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "StringTestPlugin", config);
        ptr->SetSerializer(StringSerializer::GetInstance());
    }
};

#endif // STRING_TEST_PLUGIN

class InitAttributePlg : public PluginSingleton<InitAttributePlg, Json::Value> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<InitAttributePlg, Json::Value>> ptr) override
    {
        int policyCode = 20;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "InitAttributePlg", config);
    }
};

class HandlePolicySupplierPlg : public PluginSingleton<HandlePolicySupplierPlg, Json::Value> {
public:
    ErrCode SetSupplier()
    {
        g_visit = true;
        return ERR_EDM_PARAM_ERROR;
    }

    ErrCode RemoveSupplier()
    {
        g_visit = true;
        return ERR_EDM_PARAM_ERROR;
    }

    void InitPlugin(std::shared_ptr<IPluginTemplate<HandlePolicySupplierPlg, Json::Value>> ptr) override
    {
        int policyCode = 21;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "HandlePolicySupplierPlg", config);
        ptr->SetSerializer(JsonSerializer::GetInstance());
        ptr->SetOnHandlePolicyListener(&HandlePolicySupplierPlg::SetSupplier, FuncOperateType::SET);
        ptr->SetOnHandlePolicyListener(&HandlePolicySupplierPlg::RemoveSupplier, FuncOperateType::REMOVE);
    }
};

class HandlePolicyFunctionPlg : public PluginSingleton<HandlePolicyFunctionPlg, std::string> {
public:
    ErrCode SetFunction(std::string &policyValue)
    {
        if (policyValue.empty()) {
            policyValue = "testValue";
        } else {
            policyValue = "newTestValue";
        }
        return ERR_OK;
    }

    ErrCode RemoveFunction(std::string &policyValue)
    {
        policyValue = "";
        return ERR_OK;
    }

    void InitPlugin(std::shared_ptr<IPluginTemplate<HandlePolicyFunctionPlg, std::string>> ptr) override
    {
        int policyCode = 22;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "HandlePolicyFunctionPlg", config);
        ptr->SetSerializer(StringSerializer::GetInstance());
        ptr->SetOnHandlePolicyListener(&HandlePolicyFunctionPlg::SetFunction, FuncOperateType::SET);
        ptr->SetOnHandlePolicyListener(&HandlePolicyFunctionPlg::RemoveFunction, FuncOperateType::REMOVE);
    }
};

class HandlePolicyBiFunctionPlg : public PluginSingleton<HandlePolicyBiFunctionPlg, std::string> {
public:
    ErrCode SetFunction(std::string &data, std::string &currentData, std::string &mergeData, int32_t userId)
    {
        std::string errStr{"ErrorData"};
        if (data == errStr) {
            return ERR_EDM_OPERATE_JSON;
        }
        currentData = data;
        return ERR_OK;
    }

    ErrCode RemoveFunction(std::string &data, std::string &currentData, std::string &mergeData, int32_t userId)
    {
        currentData = "";
        return ERR_OK;
    }

    void InitPlugin(std::shared_ptr<IPluginTemplate<HandlePolicyBiFunctionPlg, std::string>> ptr) override
    {
        int policyCode = 23;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "HandlePolicyBiFunctionPlg", config);
        ptr->SetSerializer(StringSerializer::GetInstance());
        ptr->SetOnHandlePolicyListener(&HandlePolicyBiFunctionPlg::SetFunction, FuncOperateType::SET);
        ptr->SetOnHandlePolicyListener(&HandlePolicyBiFunctionPlg::RemoveFunction, FuncOperateType::REMOVE);
    }
};

class HandleDoneBoolConsumerPlg : public PluginSingleton<HandleDoneBoolConsumerPlg, std::string> {
public:
    void SetDone(bool isGlobalChanged) { g_visit = true; }

    void RemoveDone(bool isGlobalChanged) { g_visit = true; }

    void InitPlugin(std::shared_ptr<IPluginTemplate<HandleDoneBoolConsumerPlg, std::string>> ptr) override
    {
        int policyCode = 24;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "HandleDoneBoolConsumerPlg", config);
        ptr->SetSerializer(StringSerializer::GetInstance());
        ptr->SetOnHandlePolicyDoneListener(&HandleDoneBoolConsumerPlg::SetDone, FuncOperateType::SET);
        ptr->SetOnHandlePolicyDoneListener(&HandleDoneBoolConsumerPlg::RemoveDone, FuncOperateType::REMOVE);
    }
};

class HandleDoneBiBoolConsumerPlg : public PluginSingleton<HandleDoneBiBoolConsumerPlg, std::string> {
public:
    void SetDone(std::string &data, bool isGlobalChanged, int32_t userId) { g_visit = true; }

    void RemoveDone(std::string &data, bool isGlobalChanged, int32_t userId) { g_visit = true; }

    void InitPlugin(std::shared_ptr<IPluginTemplate<HandleDoneBiBoolConsumerPlg, std::string>> ptr) override
    {
        int policyCode = 25;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "HandleDoneBiBoolConsumerPlg", config);
        ptr->SetSerializer(StringSerializer::GetInstance());
        ptr->SetOnHandlePolicyDoneListener(&HandleDoneBiBoolConsumerPlg::SetDone, FuncOperateType::SET);
        ptr->SetOnHandlePolicyDoneListener(&HandleDoneBiBoolConsumerPlg::RemoveDone, FuncOperateType::REMOVE);
    }
};

class AdminRemoveSupplierPlg : public PluginSingleton<AdminRemoveSupplierPlg, std::string> {
public:
    ErrCode RemoveAdmin()
    {
        g_visit = true;
        return ERR_OK;
    }

    void InitPlugin(std::shared_ptr<IPluginTemplate<AdminRemoveSupplierPlg, std::string>> ptr) override
    {
        int policyCode = 26;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "AdminRemoveSupplierPlg", config);
        ptr->SetSerializer(StringSerializer::GetInstance());
        ptr->SetOnAdminRemoveListener(&AdminRemoveSupplierPlg::RemoveAdmin);
    }
};

class AdminRemoveBiFunctionPlg : public PluginSingleton<AdminRemoveBiFunctionPlg, std::string> {
public:
    ErrCode RemoveAdmin(const std::string &adminName, std::string &data, std::string &mergeData, int32_t userId)
    {
        g_visit = true;
        return ERR_OK;
    }

    void InitPlugin(std::shared_ptr<IPluginTemplate<AdminRemoveBiFunctionPlg, std::string>> ptr) override
    {
        int policyCode = 27;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "AdminRemoveBiFunctionPlg", config);
        ptr->SetSerializer(StringSerializer::GetInstance());
        ptr->SetOnAdminRemoveListener(&AdminRemoveBiFunctionPlg::RemoveAdmin);
    }
};

class AdminRemoveDoneRunnerPlg : public PluginSingleton<AdminRemoveDoneRunnerPlg, std::string> {
public:
    void RemoveAdminDone() { g_visit = true; }

    void InitPlugin(std::shared_ptr<IPluginTemplate<AdminRemoveDoneRunnerPlg, std::string>> ptr) override
    {
        int policyCode = 28;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "AdminRemoveDoneRunnerPlg", config);
        ptr->SetSerializer(StringSerializer::GetInstance());
        ptr->SetOnAdminRemoveDoneListener(&AdminRemoveDoneRunnerPlg::RemoveAdminDone);
    }
};

class AdminRemoveDoneBiBiConsumerPlg : public PluginSingleton<AdminRemoveDoneBiBiConsumerPlg, std::string> {
public:
    void RemoveAdminDone(const std::string &adminName, std::string &data, int32_t userId) { g_visit = true; }

    void InitPlugin(std::shared_ptr<IPluginTemplate<AdminRemoveDoneBiBiConsumerPlg, std::string>> ptr) override
    {
        int policyCode = 29;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "AdminRemoveDoneBiBiConsumerPlg", config);
        ptr->SetSerializer(StringSerializer::GetInstance());
        ptr->SetOnAdminRemoveDoneListener(&AdminRemoveDoneBiBiConsumerPlg::RemoveAdminDone);
    }
};

class HandlePolicyJsonBiFunctionPlg : public PluginSingleton<HandlePolicyJsonBiFunctionPlg, Json::Value> {
public:
    ErrCode SetFunction(Json::Value &data, Json::Value &currentData, Json::Value &mergeData, int32_t userId)
    {
        currentData = data;
        return ERR_OK;
    }

    ErrCode RemoveFunction(Json::Value &data, Json::Value &currentData, Json::Value &mergeData, int32_t userId)
    {
        currentData = Json::nullValue;
        return ERR_OK;
    }

    void InitPlugin(std::shared_ptr<IPluginTemplate<HandlePolicyJsonBiFunctionPlg, Json::Value>> ptr) override
    {
        int policyCode = 30;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "HandlePolicyJsonBiFunctionPlg", config);
        ptr->SetSerializer(JsonSerializer::GetInstance());
        ptr->SetOnHandlePolicyListener(&HandlePolicyJsonBiFunctionPlg::SetFunction, FuncOperateType::SET);
        ptr->SetOnHandlePolicyListener(&HandlePolicyJsonBiFunctionPlg::RemoveFunction, FuncOperateType::REMOVE);
    }
};

class HandlePolicyBiFunctionUnsavePlg : public PluginSingleton<HandlePolicyBiFunctionUnsavePlg, Json::Value> {
public:
    ErrCode SetFunction(Json::Value &data, Json::Value &currentData, Json::Value &mergeData, int32_t userId)
    {
        currentData = data;
        return ERR_OK;
    }

    ErrCode RemoveFunction(Json::Value &data, Json::Value &currentData, Json::Value &mergeData, int32_t userId)
    {
        currentData = Json::nullValue;
        return ERR_OK;
    }

    void InitPlugin(std::shared_ptr<IPluginTemplate<HandlePolicyBiFunctionUnsavePlg, Json::Value>> ptr) override
    {
        int policyCode = 31;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "HandlePolicyBiFunctionUnsavePlg", config, false, true);
        ptr->SetSerializer(JsonSerializer::GetInstance());
        ptr->SetOnHandlePolicyListener(&HandlePolicyBiFunctionUnsavePlg::SetFunction, FuncOperateType::SET);
        ptr->SetOnHandlePolicyListener(&HandlePolicyBiFunctionUnsavePlg::RemoveFunction, FuncOperateType::REMOVE);
    }
};

class HandlePolicyReplyFunctionPlg : public PluginSingleton<HandlePolicyReplyFunctionPlg, std::string> {
public:
    ErrCode SetFunction(std::string &data, MessageParcel &reply)
    {
        g_visit = true;
        return ERR_OK;
    }

    ErrCode RemoveFunction(std::string &data, MessageParcel &reply)
    {
        g_visit = true;
        return ERR_OK;
    }

    void InitPlugin(std::shared_ptr<IPluginTemplate<HandlePolicyReplyFunctionPlg, std::string>> ptr) override
    {
        int policyCode = 32;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "HandlePolicyReplyFunctionPlg", config, false, true);
        ptr->SetSerializer(StringSerializer::GetInstance());
        ptr->SetOnHandlePolicyListener(&HandlePolicyReplyFunctionPlg::SetFunction, FuncOperateType::SET);
        ptr->SetOnHandlePolicyListener(&HandlePolicyReplyFunctionPlg::RemoveFunction, FuncOperateType::REMOVE);
    }
};
} // namespace PLUGIN

class PluginTemplateTest : public testing::Test {
protected:
    void SetUp() override;
    void TearDown() override;

private:
    std::shared_ptr<IPolicyManager> policyManager_;
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_IPLUGIN_TEMPLATE_TEST_H
