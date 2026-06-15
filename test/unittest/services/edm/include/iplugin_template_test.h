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

#include "array_string_serializer.h"
#include "basic_bool_plugin.h"
#include "func_code_utils.h"
#include "iplugin.h"
#include "cjson_serializer.h"
#include "map_string_serializer.h"
#define private public
#define protected public
#include "plugin_manager.h"
#include "plugin_singleton.h"
#undef protected
#undef private

namespace OHOS {
namespace EDM {
namespace TEST {
static bool g_visit = false;
namespace PLUGIN {

#ifndef CJSON_TEST_SERIALIZER
#define CJSON_TEST_SERIALIZER

class CjsonTestSerializer : public IPolicySerializer<cJSON*>, public DelayedSingleton<CjsonTestSerializer> {
public:
    bool Deserialize(const std::string &jsonString, cJSON* &dataObj)
    {
        if (jsonString.empty()) {
            return true;
        }
        dataObj = cJSON_Parse(jsonString.c_str());
        return dataObj != nullptr;
    }

    bool Serialize(cJSON *const &dataObj, std::string &jsonString)
    {
        if (dataObj == nullptr) {
            jsonString = "";
            return true;
        }
        char *cJsonStr = cJSON_Print(dataObj);
        if (cJsonStr != nullptr) {
            jsonString = std::string(cJsonStr);
            cJSON_free(cJsonStr);
        }
        return !jsonString.empty();
    }

    bool GetPolicy(MessageParcel &data, cJSON* &result)
    {
        std::string jsonString = data.ReadString();
        return Deserialize(jsonString, result);
    }

    bool WritePolicy(MessageParcel &reply, cJSON* &result)
    {
        std::string jsonString;
        if (!Serialize(result, jsonString)) {
            return false;
        }
        return reply.WriteString(jsonString);
    }

    bool MergePolicy(std::vector<cJSON*> &data, cJSON* &result)
    {
        return true;
    }
};

#endif // CJSON_TEST_SERIALIZER

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

class BoolTestPlugin : public BasicBoolPlugin {
public:
    BoolTestPlugin()
    {
        int policyCode = 11;
        policyCode_ = policyCode;
        policyName_ = "BoolTestPlugin";
        permissionConfig_ = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
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

#ifndef JSON_TEST_PLUGIN
#define JSON_TEST_PLUGIN

class JsonTestPlugin : public PluginSingleton<JsonTestPlugin, cJSON*> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<JsonTestPlugin, cJSON*>> ptr) override
    {
        int policyCode = 14;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "JsonTestPlugin", config);
        ptr->SetSerializer(CjsonSerializer::GetInstance());
    }
};

#endif // JSON_TEST_PLUGIN

#ifndef STRING_TEST_PLUGIN
#define STRING_TEST_PLUGIN

class StringTestPlugin : public IPlugin {
public:
    StringTestPlugin()
    {
        policyCode_ = 15;
        policyName_ = "StringTestPlugin";
        permissionConfig_ = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    }
};

#endif // STRING_TEST_PLUGIN

class InitAttributePlg : public PluginSingleton<InitAttributePlg, cJSON*> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<InitAttributePlg, cJSON*>> ptr) override
    {
        int policyCode = 20;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "InitAttributePlg", config);
    }
};

class HandlePolicySupplierPlg : public PluginSingleton<HandlePolicySupplierPlg, cJSON*> {
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

    void InitPlugin(std::shared_ptr<IPluginTemplate<HandlePolicySupplierPlg, cJSON*>> ptr) override
    {
        int policyCode = 21;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "HandlePolicySupplierPlg", config);
        ptr->SetSerializer(CjsonTestSerializer::GetInstance());
        ptr->SetOnHandlePolicyListener(&HandlePolicySupplierPlg::SetSupplier, FuncOperateType::SET);
        ptr->SetOnHandlePolicyListener(&HandlePolicySupplierPlg::RemoveSupplier, FuncOperateType::REMOVE);
    }
};

class HandlePolicyFunctionPlg : public IPlugin {
public:
    HandlePolicyFunctionPlg()
    {
        policyCode_ = 22;
        policyName_ = "HandlePolicyFunctionPlg";
        permissionConfig_ = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    }

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

    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override
    {
        std::string handleData = data.ReadString();
        uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
        FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
        ErrCode ret = ERR_OK;
        std::string currentData = policyData.policyData;
        if (type == FuncOperateType::SET) {
            ret = SetFunction(handleData);
        } else if (type == FuncOperateType::REMOVE) {
            ret = RemoveFunction(handleData);
        }
        if (FAILED(ret)) {
            return ret;
        }
        policyData.policyData = handleData;
        policyData.isChanged = policyData.policyData != currentData;
        return ERR_OK;
    }
};

class HandlePolicyBiFunctionPlg : public IPlugin {
public:
    HandlePolicyBiFunctionPlg()
    {
        policyCode_ = 23;
        policyName_ = "HandlePolicyBiFunctionPlg";
        permissionConfig_ = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    }

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

    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override
    {
        std::string handleData = data.ReadString();
        uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
        FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
        ErrCode ret = ERR_OK;
        std::string currentData = policyData.policyData;
        if (type == FuncOperateType::SET) {
            ret = SetFunction(handleData, policyData.policyData, policyData.mergePolicyData, userId);
        } else if (type == FuncOperateType::REMOVE) {
            ret = RemoveFunction(handleData, policyData.policyData, policyData.mergePolicyData, userId);
        }
        if (FAILED(ret)) {
            return ret;
        }
        policyData.isChanged = policyData.policyData != currentData;
        return ERR_OK;
    }
};

class HandleDoneBoolConsumerPlg : public IPlugin {
public:
    HandleDoneBoolConsumerPlg()
    {
        policyCode_ = 24;
        policyName_ = "HandleDoneBoolConsumerPlg";
        permissionConfig_ = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    }
    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override
    {
        g_visit = true;
    }
};

class HandleDoneBiBoolConsumerPlg : public IPlugin {
public:
    HandleDoneBiBoolConsumerPlg()
    {
        policyCode_ = 25;
        policyName_ = "HandleDoneBiBoolConsumerPlg";
        permissionConfig_ = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    }
    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override
    {
        g_visit = true;
    }
};

class AdminRemoveSupplierPlg : public IPlugin {
public:
    AdminRemoveSupplierPlg()
    {
        policyCode_ = 26;
        policyName_ = "AdminRemoveSupplierPlg";
        permissionConfig_ = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    }
    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData,
        const std::string &mergeData, int32_t userId) override
    {
        g_visit = true;
        return ERR_OK;
    }
};

class AdminRemoveBiFunctionPlg : public IPlugin {
public:
    AdminRemoveBiFunctionPlg()
    {
        policyCode_ = 27;
        policyName_ = "AdminRemoveBiFunctionPlg";
        permissionConfig_ = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    }
    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData,
        const std::string &mergeData, int32_t userId) override
    {
        g_visit = true;
        return ERR_OK;
    }
};

class AdminRemoveDoneRunnerPlg : public IPlugin {
public:
    AdminRemoveDoneRunnerPlg()
    {
        policyCode_ = 28;
        policyName_ = "AdminRemoveDoneRunnerPlg";
        permissionConfig_ = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    }
    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
        int32_t userId) override
    {
        g_visit = true;
    }
};

class AdminRemoveDoneBiBiConsumerPlg : public IPlugin {
public:
    AdminRemoveDoneBiBiConsumerPlg()
    {
        policyCode_ = 29;
        policyName_ = "AdminRemoveDoneBiBiConsumerPlg";
        permissionConfig_ = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    }
    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
        int32_t userId) override
    {
        g_visit = true;
    }
};

class HandlePolicyJsonBiFunctionPlg : public PluginSingleton<HandlePolicyJsonBiFunctionPlg, cJSON*> {
public:
    ErrCode SetFunction(cJSON*& data, cJSON*& currentData, cJSON*& mergeData, int32_t userId)
    {
        if (currentData != nullptr) {
            cJSON_Delete(currentData);
        }
        currentData = cJSON_Duplicate(data, true);
        return ERR_OK;
    }

    ErrCode RemoveFunction(cJSON*& data, cJSON*& currentData, cJSON*& mergeData, int32_t userId)
    {
        if (currentData != nullptr) {
            cJSON_Delete(currentData);
        }
        currentData = cJSON_CreateNull();
        return ERR_OK;
    }

    void InitPlugin(std::shared_ptr<IPluginTemplate<HandlePolicyJsonBiFunctionPlg, cJSON*>> ptr) override
    {
        int policyCode = 30;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "HandlePolicyJsonBiFunctionPlg", config);
        
        ptr->SetSerializer(CjsonTestSerializer::GetInstance());
        
        ptr->SetOnHandlePolicyListener(&HandlePolicyJsonBiFunctionPlg::SetFunction, FuncOperateType::SET);
        ptr->SetOnHandlePolicyListener(&HandlePolicyJsonBiFunctionPlg::RemoveFunction, FuncOperateType::REMOVE);
    }
};

class HandlePolicyBiFunctionUnsavePlg : public PluginSingleton<HandlePolicyBiFunctionUnsavePlg, cJSON*> {
public:
    ErrCode SetFunction(cJSON*& data, cJSON*& currentData, cJSON*& mergeData, int32_t userId)
    {
        if (currentData) {
            cJSON_Delete(currentData);
        }
        currentData = cJSON_Duplicate(data, true);
        return ERR_OK;
    }

    ErrCode RemoveFunction(cJSON*& data, cJSON*& currentData, cJSON*& mergeData, int32_t userId)
    {
        if (currentData) {
            cJSON_Delete(currentData);
        }
        currentData = cJSON_CreateNull();
        return ERR_OK;
    }

    void InitPlugin(std::shared_ptr<IPluginTemplate<HandlePolicyBiFunctionUnsavePlg, cJSON*>> ptr) override
    {
        int policyCode = 31;
        IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        ptr->InitAttribute(policyCode, "HandlePolicyBiFunctionUnsavePlg", config, false, true);
        
        ptr->SetSerializer(CjsonTestSerializer::GetInstance());
        ptr->SetOnHandlePolicyListener(&HandlePolicyBiFunctionUnsavePlg::SetFunction, FuncOperateType::SET);
        ptr->SetOnHandlePolicyListener(&HandlePolicyBiFunctionUnsavePlg::RemoveFunction, FuncOperateType::REMOVE);
    }
};

class HandlePolicyReplyFunctionPlg : public IPlugin {
public:
    HandlePolicyReplyFunctionPlg()
    {
        policyCode_ = 32;
        policyName_ = "HandlePolicyReplyFunctionPlg";
        permissionConfig_ = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
        needSave_ = false;
    }

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

    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override
    {
        std::string handleData = data.ReadString();
        uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
        FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
        ErrCode ret = ERR_OK;
        std::string currentData = policyData.policyData;
        if (type == FuncOperateType::SET) {
            ret = SetFunction(handleData, reply);
        } else if (type == FuncOperateType::REMOVE) {
            ret = RemoveFunction(handleData, reply);
        }
        if (FAILED(ret)) {
            return ret;
        }
        policyData.policyData = handleData;
        policyData.isChanged = policyData.policyData != currentData;
        return ERR_OK;
    }
};

class OtherServiceStartRunnerPlg : public IPlugin {
public:
    OtherServiceStartRunnerPlg()
    {
        policyCode_ = 33;
        policyName_ = "OtherServiceStartRunnerPlg";
        permissionConfig_ = IPlugin::PolicyPermissionConfig("ohos.permission.EDM_TEST_PERMISSION",
            IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    }
    void OnOtherServiceStart(int32_t systemAbilityId) override
    {
        g_visit = true;
    }
};
} // namespace PLUGIN

class PluginTemplateTest : public testing::Test {
protected:
    void SetUp() override;
    void TearDown() override;
    static void SetUpTestSuite();

private:
    std::shared_ptr<IPolicyManager> policyManager_;
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_IPLUGIN_TEMPLATE_TEST_H