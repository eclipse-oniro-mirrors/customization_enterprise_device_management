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

#include "array_odd_burn_usb_device_serializer.h"

#include <algorithm>
#include <cinttypes>
#include "cjson_check.h"
#include "edm_constants.h"
#include "edm_log.h"
#include "ipc_skeleton.h"
#include "odd_burn_usb_device.h"

namespace OHOS {
namespace EDM {

std::vector<OddBurnUsbDevice> ArrayOddBurnUsbDeviceSerializer::SetUnionPolicyData(
    std::vector<OddBurnUsbDevice> &data, std::vector<OddBurnUsbDevice> &currentData)
{
    std::vector<OddBurnUsbDevice> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_union(data.begin(), data.end(), currentData.begin(), currentData.end(),
        std::back_inserter(mergeData));
    return mergeData;
}

std::vector<OddBurnUsbDevice> ArrayOddBurnUsbDeviceSerializer::SetDifferencePolicyData(
    std::vector<OddBurnUsbDevice> &data, std::vector<OddBurnUsbDevice> &currentData)
{
    std::vector<OddBurnUsbDevice> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_difference(currentData.begin(), currentData.end(), data.begin(), data.end(),
        std::back_inserter(mergeData));
    return mergeData;
}

bool ArrayOddBurnUsbDeviceSerializer::Deserialize(const std::string &jsonString,
    std::vector<OddBurnUsbDevice> &dataObj)
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
    if (arraySize < 0) {
        EDMLOGE("Deserialize data size = %{public}d is invalid", arraySize);
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

        cJSON *vendorId = cJSON_GetObjectItem(item, "vendorId");
        cJSON *productId = cJSON_GetObjectItem(item, "productId");
        cJSON *serial = cJSON_GetObjectItem(item, "serial");

        if (!vendorId || !productId || !cJSON_IsNumber(vendorId) || !cJSON_IsNumber(productId)) {
            EDMLOGE("Invalid ODD burn USB device data.");
            cJSON_Delete(root);
            return false;
        }

        OddBurnUsbDevice device;
        device.SetVendorId(vendorId->valueint);
        device.SetProductId(productId->valueint);
        if (serial != nullptr && cJSON_IsString(serial)) {
            device.SetSerial(serial->valuestring);
        }
        dataObj[i] = device;
    }

    cJSON_Delete(root);
    return true;
}

bool ArrayOddBurnUsbDeviceSerializer::Serialize(const std::vector<OddBurnUsbDevice> &dataObj,
    std::string &jsonString)
{
    if (dataObj.empty()) {
        jsonString = "";
        return true;
    }

    cJSON *root = nullptr;
    CJSON_CREATE_ARRAY_AND_CHECK(root, false);

    for (const auto &device : dataObj) {
        cJSON *item = nullptr;
        CJSON_CREATE_OBJECT_AND_CHECK_AND_CLEAR(item, false, root);

        if (!cJSON_AddNumberToObject(item, "vendorId", device.GetVendorId()) ||
            !cJSON_AddNumberToObject(item, "productId", device.GetProductId()) ||
            !cJSON_AddStringToObject(item, "serial", device.GetSerial().c_str())) {
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

bool ArrayOddBurnUsbDeviceSerializer::GetPolicy(MessageParcel &data,
    std::vector<OddBurnUsbDevice> &result)
{
    return ReadRawDataFromParcel(data, result);
}

bool ArrayOddBurnUsbDeviceSerializer::WritePolicy(MessageParcel &reply,
    std::vector<OddBurnUsbDevice> &result)
{
    return WriteRawDataToParcel(reply, result);
}

bool ArrayOddBurnUsbDeviceSerializer::MergePolicy(std::vector<std::vector<OddBurnUsbDevice>> &data,
    std::vector<OddBurnUsbDevice> &result)
{
    std::set<OddBurnUsbDevice> stData;
    for (const auto &dataItem : data) {
        for (const auto &item : dataItem) {
            stData.insert(item);
        }
    }
    result.assign(stData.begin(), stData.end());
    return true;
}

bool ArrayOddBurnUsbDeviceSerializer::WriteRawDataToParcel(MessageParcel &parcel,
    const std::vector<OddBurnUsbDevice> &devices)
{
    std::string jsonString;
    if (!Serialize(devices, jsonString)) {
        EDMLOGE("WriteRawDataToParcel: Serialize failed");
        return false;
    }
    int32_t dataSize = static_cast<int32_t>(jsonString.size());
    if (!parcel.WriteInt32(dataSize)) {
        EDMLOGE("WriteRawDataToParcel: write dataSize failed");
        return false;
    }
    if (dataSize == 0) {
        EDMLOGI("WriteRawDataToParcel: empty devices, skip WriteRawData");
        return true;
    }
    if (!parcel.WriteRawData(jsonString.data(), static_cast<size_t>(dataSize))) {
        EDMLOGE("WriteRawDataToParcel: WriteRawData failed, size=%{public}d", dataSize);
        return false;
    }
    EDMLOGI("WriteRawDataToParcel: write %{public}zu devices, dataSize=%{public}d", devices.size(), dataSize);
    return true;
}

bool ArrayOddBurnUsbDeviceSerializer::ReadRawDataFromParcel(MessageParcel &parcel,
    std::vector<OddBurnUsbDevice> &devices)
{
    int32_t dataSize = parcel.ReadInt32();
    if (dataSize == 0) {
        EDMLOGI("ReadRawDataFromParcel: no data");
        return true;
    }
    if (dataSize < 0) {
        EDMLOGE("ReadRawDataFromParcel: invalid dataSize=%{public}d", dataSize);
        return false;
    }

    const void *rawData = parcel.ReadRawData(static_cast<size_t>(dataSize));
    if (rawData == nullptr) {
        EDMLOGE("ReadRawDataFromParcel: ReadRawData failed, size=%{public}d", dataSize);
        return false;
    }

    std::string jsonString(static_cast<const char *>(rawData), static_cast<size_t>(dataSize));
    if (!Deserialize(jsonString, devices)) {
        EDMLOGE("ReadRawDataFromParcel: Deserialize failed, dataSize=%{public}d", dataSize);
        return false;
    }
    EDMLOGI("ReadRawDataFromParcel: read %{public}zu devices", devices.size());
    return true;
}
} // namespace EDM
} // namespace OHOS
