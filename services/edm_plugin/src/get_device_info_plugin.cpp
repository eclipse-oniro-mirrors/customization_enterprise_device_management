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

#include "get_device_info_plugin.h"

#ifdef TELEPHONY_CORE_EDM_ENABLE
#include "core_service_client.h"
#endif
#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "edm_utils.h"
#include "parameter.h"
#include "plugin_manager.h"
#include "string_serializer.h"

namespace OHOS {
namespace EDM {
const std::string KEY_DEVICE_NAME = "settings.general.device_name";

const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(GetDeviceInfoPlugin::GetPlugin());

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
        std::string name;
        ErrCode code = EdmDataAbilityUtils::GetStringFromSettingsDataShare(KEY_DEVICE_NAME, name);
        if (FAILED(code)) {
            EDMLOGD("GetDeviceInfoPlugin::get device name from database failed : %{public}d.", code);
            reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        if (name.empty()) {
            name = GetMarketName();
        }
        reply.WriteInt32(ERR_OK);
        reply.WriteString(name);
        return ERR_OK;
    }
    if (label == EdmConstants::DeviceInfo::DEVICE_SERIAL) {
        std::string serial = GetSerial();
        reply.WriteInt32(ERR_OK);
        reply.WriteString(serial);
        return ERR_OK;
    }
#ifdef TELEPHONY_CORE_EDM_ENABLE
    if (label == EdmConstants::DeviceInfo::SIM_INFO) {
        std::string simInfo;
        int32_t ret = GetSimInfo(simInfo);
        if (FAILED(ret)) {
            EDMLOGD("GetDeviceInfoPlugin::get sim info failed : %{public}d.", ret);
            reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        reply.WriteInt32(ERR_OK);
        reply.WriteString(simInfo);
        return ERR_OK;
    }
#endif
    reply.WriteInt32(EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    if (GetPlugin()->GetExtensionPlugin() != nullptr) {
        reply.WriteString(label);
    }
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

#ifdef TELEPHONY_CORE_EDM_ENABLE
ErrCode GetDeviceInfoPlugin::GetSimInfo(std::string &info)
{
    cJSON *json = cJSON_CreateArray();
    if (json == nullptr) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    GetSimInfoBySlotId(EdmConstants::DeviceInfo::SIM_SLOT_ID_0, json);
    GetSimInfoBySlotId(EdmConstants::DeviceInfo::SIM_SLOT_ID_1, json);
    char *jsonStr = cJSON_PrintUnformatted(json);
    if (jsonStr == nullptr) {
        cJSON_Delete(json);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    info = std::string(jsonStr);
    cJSON_Delete(json);
    cJSON_free(jsonStr);
    return ERR_OK;
}

void GetDeviceInfoPlugin::GetSimInfoBySlotId(int32_t slotId, cJSON *simJson)
{
    cJSON *slotJson = cJSON_CreateObject();
    if (slotJson == nullptr) {
        return;
    }
    cJSON_AddNumberToObject(slotJson, EdmConstants::DeviceInfo::SIM_SLOT_ID.c_str(), slotId);
    std::u16string meid;
    auto &telephonyService = Telephony::CoreServiceClient::GetInstance();
    int32_t meidRet = telephonyService.GetMeid(slotId, meid);
    if (FAILED(meidRet)) {
        EDMLOGD("GetDeviceInfoPlugin::get sim meid failed: %{public}d.", meidRet);
    }
    cJSON_AddStringToObject(slotJson, EdmConstants::DeviceInfo::SIM_MEID.c_str(), EdmUtils::Utf16ToUtf8(meid).c_str());

    std::u16string imsi;
    int32_t imsiRet = telephonyService.GetIMSI(slotId, imsi);
    if (FAILED(imsiRet)) {
        EDMLOGD("GetDeviceInfoPlugin::get sim imsi failed: %{public}d.", imsiRet);
    }
    cJSON_AddStringToObject(slotJson, EdmConstants::DeviceInfo::SIM_IMSI.c_str(), EdmUtils::Utf16ToUtf8(imsi).c_str());

    std::u16string iccId;
    int32_t iccIdRet = telephonyService.GetSimIccId(slotId, iccId);
    if (FAILED(iccIdRet)) {
        EDMLOGD("GetDeviceInfoPlugin::get sim iccid failed: %{public}d.", iccIdRet);
    }
    cJSON_AddStringToObject(slotJson, EdmConstants::DeviceInfo::SIM_ICCID.c_str(),
        EdmUtils::Utf16ToUtf8(iccId).c_str());

    std::u16string imei;
    int32_t imeiRet = telephonyService.GetImei(slotId, imei);
    if (FAILED(imeiRet)) {
        EDMLOGD("GetDeviceInfoPlugin::get sim imei failed: %{public}d.", imeiRet);
    }
    cJSON_AddStringToObject(slotJson, EdmConstants::DeviceInfo::SIM_IMEI.c_str(), EdmUtils::Utf16ToUtf8(imei).c_str());
    cJSON_AddItemToArray(simJson, slotJson);
}
#endif
} // namespace EDM
} // namespace OHOS
