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

#include "array_usb_device_type_serializer.h"
#include "cJSON.h"
#include "cjson_check.h"
#include "edm_constants.h"

namespace OHOS {
namespace EDM {
const std::string BASE_CLASS = "baseClass";
const std::string SUB_CLASS = "subClass";
const std::string PROTOCOL = "protocol";
const std::string IS_DEVICE_TYPE = "isDeviceType";
constexpr int32_t DEVICE_TYPE_MIN_VALUE = 0;
constexpr int32_t DEVICE_TYPE_MAX_VALUE = 255;

std::vector<USB::UsbDeviceType> ArrayUsbDeviceTypeSerializer::SetUnionPolicyData(
    std::vector<USB::UsbDeviceType> &data, std::vector<USB::UsbDeviceType> &currentData)
{
    std::vector<USB::UsbDeviceType> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_union(data.begin(), data.end(), currentData.begin(), currentData.end(), back_inserter(mergeData));
    return mergeData;
}

std::vector<USB::UsbDeviceType> ArrayUsbDeviceTypeSerializer::SetDifferencePolicyData(
    std::vector<USB::UsbDeviceType> &data, std::vector<USB::UsbDeviceType> &currentData)
{
    std::vector<USB::UsbDeviceType> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_difference(currentData.begin(), currentData.end(), data.begin(), data.end(), back_inserter(mergeData));
    return mergeData;
}

bool ArrayUsbDeviceTypeSerializer::Deserialize(const std::string &jsonString, std::vector<USB::UsbDeviceType> &dataObj)
{
    if (jsonString.empty()) {
        return true;
    }
    cJSON* root = cJSON_Parse(jsonString.c_str());
    if (root == nullptr) {
        EDMLOGE("ArrayUsbDeviceTypeSerializer Deserialize: root is null!");
        return false;
    }
    cJSON* item;
    cJSON_ArrayForEach(item, root) {
        cJSON* baseClass = cJSON_GetObjectItem(item, BASE_CLASS.c_str());
        cJSON* subClass = cJSON_GetObjectItem(item, SUB_CLASS.c_str());
        cJSON* protocol = cJSON_GetObjectItem(item, PROTOCOL.c_str());
        cJSON* isDeviceType = cJSON_GetObjectItem(item, IS_DEVICE_TYPE.c_str());
        if (baseClass == nullptr || subClass == nullptr || protocol == nullptr || isDeviceType == nullptr) {
            EDMLOGI("ArrayUsbDeviceTypeSerializer::cJSON_GetObjectItem get null.");
            cJSON_Delete(root);
            return false;
        }
        if (!cJSON_IsNumber(baseClass) || !cJSON_IsNumber(subClass) || !cJSON_IsNumber(protocol) ||
            !cJSON_IsBool(isDeviceType)) {
            EDMLOGI("ArrayUsbDeviceTypeSerializer::cJSON_GetObjectItem get error type.");
            cJSON_Delete(root);
            return false;
        }
        USB::UsbDeviceType usbDeviceType;
        usbDeviceType.baseClass = cJSON_GetNumberValue(baseClass);
        usbDeviceType.subClass = cJSON_GetNumberValue(subClass);
        usbDeviceType.protocol = cJSON_GetNumberValue(protocol);
        usbDeviceType.isDeviceType = cJSON_IsTrue(isDeviceType);
        dataObj.emplace_back(usbDeviceType);
    }

    cJSON_Delete(root);
    return true;
}

bool ArrayUsbDeviceTypeSerializer::Serialize(const std::vector<USB::UsbDeviceType> &dataObj, std::string &jsonString)
{
    if (dataObj.empty()) {
        return true;
    }
    if (dataObj.size() > EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE) {
        EDMLOGE("ArrayUsbDeviceIdSerializer:Serialize size=[%{public}zu] is too large", dataObj.size());
        return false;
    }
    cJSON* root = nullptr;
    CJSON_CREATE_ARRAY_AND_CHECK(root, false);
    for (auto& it : dataObj) {
        cJSON* item = nullptr;
        CJSON_CREATE_OBJECT_AND_CHECK_AND_CLEAR(item, false, root);
        cJSON_AddNumberToObject(item, BASE_CLASS.c_str(), it.baseClass);
        cJSON_AddNumberToObject(item, SUB_CLASS.c_str(), it.subClass);
        cJSON_AddNumberToObject(item, PROTOCOL.c_str(), it.protocol);
        cJSON_AddBoolToObject(item, IS_DEVICE_TYPE.c_str(), it.isDeviceType);
        cJSON_AddItemToArray(root, item);
    }
    char *cJsonStr = cJSON_Print(root);
    if (cJsonStr != nullptr) {
        jsonString = std::string(cJsonStr);
        cJSON_free(cJsonStr);
    }
    cJSON_Delete(root);
    return true;
}

bool ArrayUsbDeviceTypeSerializer::GetPolicy(MessageParcel &data, std::vector<USB::UsbDeviceType> &result)
{
    uint32_t size = data.ReadUint32();
    if (size > EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE) {
        EDMLOGE("ArrayUsbDeviceIdSerializer:GetPolicy size=[%{public}u] is too large", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        USB::UsbDeviceType usbDeviceType;
        if (!USB::UsbDeviceType::Unmarshalling(data, usbDeviceType)) {
            EDMLOGE("DisallowUsbDevicesPlugin GetDataByParcel::read parcel fail");
            return false;
        }
        if (usbDeviceType.baseClass < DEVICE_TYPE_MIN_VALUE || usbDeviceType.baseClass > DEVICE_TYPE_MAX_VALUE ||
            usbDeviceType.subClass < DEVICE_TYPE_MIN_VALUE || usbDeviceType.subClass > DEVICE_TYPE_MAX_VALUE ||
            usbDeviceType.protocol < DEVICE_TYPE_MIN_VALUE || usbDeviceType.protocol > DEVICE_TYPE_MAX_VALUE) {
            EDMLOGE("DisallowUsbDevicesPlugin GetDataByParcel: baseClass or subClass or protocol is invalid");
            return false;
        }
        result.emplace_back(usbDeviceType);
    }
    return true;
}

bool ArrayUsbDeviceTypeSerializer::WritePolicy(MessageParcel &reply, std::vector<USB::UsbDeviceType> &result)
{
    return true;
}

bool ArrayUsbDeviceTypeSerializer::MergePolicy(std::vector<std::vector<USB::UsbDeviceType>> &data,
    std::vector<USB::UsbDeviceType> &result)
{
    std::set<USB::UsbDeviceType> stData;
    for (const auto &dataItem : data) {
        for (const auto &item : dataItem) {
            stData.insert(item);
        }
    }
    result.assign(stData.begin(), stData.end());
    return true;
}
} // namespace EDM
} // namespace OHOS