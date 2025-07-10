/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "array_usb_device_id_serializer.h"
#include "cjson_check.h"
#include "edm_constants.h"
#include "usb_device_id.h"

namespace OHOS {
namespace EDM {

std::vector<UsbDeviceId> ArrayUsbDeviceIdSerializer::SetUnionPolicyData(std::vector<UsbDeviceId> &data,
    std::vector<UsbDeviceId> &currentData)
{
    std::vector<UsbDeviceId> mergeData;
    std::sort(data.begin(), data.end(), Comp());
    std::sort(currentData.begin(), currentData.end(), Comp());
    std::set_union(data.begin(), data.end(), currentData.begin(), currentData.end(), back_inserter(mergeData), Comp());
    return mergeData;
}

std::vector<UsbDeviceId> ArrayUsbDeviceIdSerializer::SetDifferencePolicyData(std::vector<UsbDeviceId> &data,
    std::vector<UsbDeviceId> &currentData)
{
    std::vector<UsbDeviceId> mergeData;
    std::sort(data.begin(), data.end(), Comp());
    std::sort(currentData.begin(), currentData.end(), Comp());
    std::set_difference(currentData.begin(), currentData.end(), data.begin(), data.end(), back_inserter(mergeData),
        Comp());
    return mergeData;
}

bool ArrayUsbDeviceIdSerializer::Deserialize(const std::string &jsonString, std::vector<UsbDeviceId> &dataObj)
{
    if (jsonString.empty()) {
        return true;
    }

    cJSON *root = cJSON_Parse(jsonString.c_str());
    if (root == nullptr) {
        EDMLOGE("JSON parse error");
        return false;
    }

    if (!cJSON_IsArray(root)) {
        EDMLOGE("JSON is not an array.");
        cJSON_Delete(root);
        return false;
    }

    const int arraySize = cJSON_GetArraySize(root);
    if (arraySize > EdmConstants::ALLOWED_USB_DEVICES_MAX_SIZE) {
        EDMLOGE("ArrayUsbDeviceIdSerializer Deserialize data size=%{public}d is too large", arraySize);
        cJSON_Delete(root);
        return false;
    }

    dataObj.resize(arraySize);

    for (int i = 0; i < arraySize; ++i) {
        cJSON *item = cJSON_GetArrayItem(root, i);
        if (item == nullptr) {
            EDMLOGE("Invalid item.");
            cJSON_Delete(root);
            return false;
        }

        cJSON *vendor_id = cJSON_GetObjectItem(item, "vendorId");
        cJSON *product_id = cJSON_GetObjectItem(item, "productId");

        if (!vendor_id || !product_id || !cJSON_IsNumber(vendor_id) || !cJSON_IsNumber(product_id)) {
            EDMLOGE("Invalid USB device data.");
            cJSON_Delete(root);
            return false;
        }

        UsbDeviceId device;
        device.SetVendorId(vendor_id->valueint);
        device.SetProductId(product_id->valueint);
        dataObj[i] = device;
    }

    cJSON_Delete(root);
    return true;
}

bool ArrayUsbDeviceIdSerializer::Serialize(const std::vector<UsbDeviceId> &dataObj, std::string &jsonString)
{
    if (dataObj.empty()) {
        jsonString = "";
        return true;
    }

    cJSON *root = nullptr;
    CJSON_CREATE_ARRAY_AND_CHECK(root, false);

    for (const auto &device : dataObj) {
        cJSON* item = nullptr;
        CJSON_CREATE_OBJECT_AND_CHECK_AND_CLEAR(item, false, root);

        if (!cJSON_AddNumberToObject(item, "vendorId", device.GetVendorId()) ||
        !cJSON_AddNumberToObject(item, "productId", device.GetProductId())) {
            cJSON_Delete(item);
            cJSON_Delete(root);
            return false;
        }
        CJSON_ADD_ITEM_TO_ARRAY_AND_CHECK_AND_CLEAR(item, root, false);
    }

    char *jsonStr = cJSON_Print(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return false;
    }

    jsonString = jsonStr;
    cJSON_free(jsonStr);
    cJSON_Delete(root);
    return true;
}

bool ArrayUsbDeviceIdSerializer::GetPolicy(MessageParcel &data, std::vector<UsbDeviceId> &result)
{
    uint32_t size = data.ReadUint32();
    if (size > EdmConstants::ALLOWED_USB_DEVICES_MAX_SIZE) {
        EDMLOGE("ArrayUsbDeviceIdSerializer:GetPolicy size=[%{public}u] is too large", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        UsbDeviceId usbDeviceId;
        if (!UsbDeviceId::Unmarshalling(data, usbDeviceId)) {
            EDMLOGE("ArrayUsbDeviceIdSerializer::GetPolicy read parcel fail");
            return false;
        }
        result.emplace_back(usbDeviceId);
    }
    return true;
}

bool ArrayUsbDeviceIdSerializer::WritePolicy(MessageParcel &reply, std::vector<UsbDeviceId> &result)
{
    std::for_each(result.begin(), result.end(), [&](const auto usbDeviceId) {
        usbDeviceId.Marshalling(reply);
    });
    return true;
}

bool ArrayUsbDeviceIdSerializer::MergePolicy(std::vector<std::vector<UsbDeviceId>> &data,
    std::vector<UsbDeviceId> &result)
{
    std::set<UsbDeviceId> stData;
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