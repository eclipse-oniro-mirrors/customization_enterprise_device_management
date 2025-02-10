/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "get_device_info_plugin.h"

#ifdef TELEPHONY_CORE_EDM_ENABLE
#include "core_service_client.h"
#endif
#include "cjson_check.h"
#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "edm_utils.h"
#include "external_manager_factory.h"
#include "parameter.h"
#include "iplugin_manager.h"
#include "string_serializer.h"

namespace OHOS {
namespace EDM {
const std::string KEY_DEVICE_NAME = "settings.general.display_device_name";

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(GetDeviceInfoPlugin::GetPlugin());

void GetDeviceInfoPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<GetDeviceInfoPlugin, std::string>> ptr)
{
    EDMLOGI("GetDeviceInfoPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::GET_DEVICE_INFO, "get_device_info",
        "ohos.permission.ENTERPRISE_GET_DEVICE_INFO", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
}

ErrCode GetDeviceInfoPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::string label = data.ReadString();
    EDMLOGI("GetDeviceInfoPlugin OnGetPolicy GetDeviceInfo %{public}s", label.c_str());
    if (label == EdmConstants::DeviceInfo::DEVICE_NAME) {
        return GetDeviceName(reply);
    }
    if (label == EdmConstants::DeviceInfo::DEVICE_SERIAL) {
        return GetDeviceSerial(reply);
    }
#ifdef TELEPHONY_CORE_EDM_ENABLE
    if (label == EdmConstants::DeviceInfo::SIM_INFO) {
        return GetSimInfo(reply);
    }
#endif
    reply.WriteInt32(EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    if (GetPlugin()->GetExtensionPlugin() != nullptr) {
        reply.WriteString(label);
    }
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

std::shared_ptr<IExternalManagerFactory> GetDeviceInfoPlugin::GetExternalManagerFactory()
{
    if (externalManagerFactory_ == nullptr) {
        externalManagerFactory_ = std::make_shared<ExternalManagerFactory>();
    }
    return externalManagerFactory_;
}

ErrCode GetDeviceInfoPlugin::GetDeviceName(MessageParcel &reply)
{
    std::string name;
    std::vector<int32_t> ids;
    std::string userId;
    ErrCode code = GetExternalManagerFactory()->CreateOsAccountManager()->QueryActiveOsAccountIds(ids);
    if (SUCCEEDED(code) && !ids.empty()) {
        userId = std::to_string(ids.at(0));
    } else {
        EDMLOGE("GetDeviceInfoPlugin::get current account id failed : %{public}d.", code);
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string settingsDataUri = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_" +
        userId + "?Proxy=true";
    code = EdmDataAbilityUtils::GetStringFromSettingsDataShare(settingsDataUri, KEY_DEVICE_NAME, name);
    if (FAILED(code)) {
        EDMLOGE("GetDeviceInfoPlugin::get device name from database failed : %{public}d.", code);
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (name.empty()) {
        const char *marketName = GetMarketName();
        if (marketName == nullptr) {
            EDMLOGE("GetDeviceInfoPlugin GetDeviceName Failed. GetMarketName is nullptr.");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        name = marketName;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteString(name);
    return ERR_OK;
}

ErrCode GetDeviceInfoPlugin::GetDeviceSerial(MessageParcel &reply)
{
    const char* serialPtr = GetSerial();
    if (serialPtr == nullptr) {
        EDMLOGE("GetDeviceInfoPlugin GetDeviceSerial Failed. GetSerial is nullptr.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string serial = serialPtr;
    reply.WriteInt32(ERR_OK);
    reply.WriteString(serial);
    return ERR_OK;
}

#ifdef TELEPHONY_CORE_EDM_ENABLE
ErrCode GetDeviceInfoPlugin::GetSimInfo(MessageParcel &reply)
{
    cJSON *json = cJSON_CreateArray();
    if (json == nullptr) {
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (!GetSimInfoBySlotId(EdmConstants::DeviceInfo::SIM_SLOT_ID_0, json) ||
        !GetSimInfoBySlotId(EdmConstants::DeviceInfo::SIM_SLOT_ID_1, json)) {
        cJSON_Delete(json);
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    char *jsonStr = cJSON_PrintUnformatted(json);
    if (jsonStr == nullptr) {
        cJSON_Delete(json);
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string info = std::string(jsonStr);
    cJSON_Delete(json);
    cJSON_free(jsonStr);
    reply.WriteInt32(ERR_OK);
    reply.WriteString(info);
    return ERR_OK;
}

bool GetDeviceInfoPlugin::GetSimInfoBySlotId(int32_t slotId, cJSON *simJson)
{
    cJSON *slotJson = nullptr;
    CJSON_CREATE_OBJECT_AND_CHECK(slotJson, false);
    cJSON_AddNumberToObject(slotJson, EdmConstants::DeviceInfo::SIM_SLOT_ID, slotId);
    std::u16string meid;
    auto &telephonyService = Telephony::CoreServiceClient::GetInstance();
    int32_t meidRet = telephonyService.GetMeid(slotId, meid);
    if (FAILED(meidRet)) {
        EDMLOGD("GetDeviceInfoPlugin::get sim meid failed: %{public}d.", meidRet);
    }
    cJSON_AddStringToObject(slotJson, EdmConstants::DeviceInfo::SIM_MEID, EdmUtils::Utf16ToUtf8(meid).c_str());

    std::u16string imsi;
    int32_t imsiRet = telephonyService.GetIMSI(slotId, imsi);
    if (FAILED(imsiRet)) {
        EDMLOGD("GetDeviceInfoPlugin::get sim imsi failed: %{public}d.", imsiRet);
    }
    cJSON_AddStringToObject(slotJson, EdmConstants::DeviceInfo::SIM_IMSI, EdmUtils::Utf16ToUtf8(imsi).c_str());

    std::u16string iccId;
    int32_t iccIdRet = telephonyService.GetSimIccId(slotId, iccId);
    if (FAILED(iccIdRet)) {
        EDMLOGD("GetDeviceInfoPlugin::get sim iccid failed: %{public}d.", iccIdRet);
    }
    cJSON_AddStringToObject(slotJson, EdmConstants::DeviceInfo::SIM_ICCID, EdmUtils::Utf16ToUtf8(iccId).c_str());

    std::u16string imei;
    int32_t imeiRet = telephonyService.GetImei(slotId, imei);
    if (FAILED(imeiRet)) {
        EDMLOGD("GetDeviceInfoPlugin::get sim imei failed: %{public}d.", imeiRet);
    }
    cJSON_AddStringToObject(slotJson, EdmConstants::DeviceInfo::SIM_IMEI, EdmUtils::Utf16ToUtf8(imei).c_str());
    if (!cJSON_AddItemToArray(simJson, slotJson)) {
        cJSON_Delete(slotJson);
        return false;
    }
    return true;
}
#endif
} // namespace EDM
} // namespace OHOS
