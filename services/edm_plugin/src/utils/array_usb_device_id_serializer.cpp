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
#include "edm_constants.h"
#include "json/json.h"
#include "usb_device_id.h"

namespace OHOS {
namespace EDM {
constexpr int32_t ESCAPED_STRING_SUFFIX_LENGTH = 4;

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
    Json::Value root;
    Json::String err;
    Json::CharReaderBuilder builder;
    const std::unique_ptr<Json::CharReader> charReader(builder.newCharReader());
    if (!charReader->parse(jsonString.c_str(), jsonString.c_str() + jsonString.length(), &root, &err)) {
        return false;
    }
    if (!root.isArray()) {
        EDMLOGE("ArrayUsbDeviceIdSerializer Deserialize root is not array");
        return false;
    }
    dataObj = std::vector<UsbDeviceId>(root.size());
    for (std::uint32_t i = 0; i < root.size(); ++i) {
        Json::StreamWriterBuilder writerBuilder;
        std::string valueJsonString = Json::writeString(writerBuilder, root[i]);
        std::string::size_type pos = 0;
        while ((pos = valueJsonString.find("\\\"")) != std::string::npos) {
            valueJsonString.replace(pos, 1, "");
        }
        valueJsonString = valueJsonString.substr(1, valueJsonString.length() - ESCAPED_STRING_SUFFIX_LENGTH);
        UsbDeviceId value;
        Json::Value item;
        Json::Reader reader;
        if (!reader.parse(valueJsonString.data(), valueJsonString.data() + valueJsonString.length(), item)) {
            EDMLOGE("ArrayUsbDeviceIdSerializer Deserialize reader can not parse, i = %{public}d", i);
            return false;
        }
        if (!item["vendorId"].isConvertibleTo(Json::intValue) || !item["productId"].isConvertibleTo(Json::intValue)) {
            EDMLOGE("ArrayUsbDeviceIdSerializer Deserialize vendorId or productId can not parse.");
            return false;
        }
        value.SetVendorId(item["vendorId"].asInt());
        value.SetProductId(item["productId"].asInt());
        dataObj.at(i) = value;
    }
    return true;
}

bool ArrayUsbDeviceIdSerializer::Serialize(const std::vector<UsbDeviceId> &dataObj, std::string &jsonString)
{
    if (dataObj.empty()) {
        jsonString = "";
        return true;
    }
    Json::Value arrayData(Json::arrayValue);
    for (std::uint32_t i = 0; i < dataObj.size(); ++i) {
        std::string itemJson;
        UsbDeviceId item = dataObj.at(i);
        Json::Value root;
        root["vendorId"] = item.GetVendorId();
        root["productId"] = item.GetProductId();
        Json::FastWriter writer;
        itemJson = writer.write(root);
        arrayData[i] = itemJson;
    }
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "    ";
    jsonString = Json::writeString(builder, arrayData);
    return true;
}

bool ArrayUsbDeviceIdSerializer::GetPolicy(MessageParcel &data, std::vector<UsbDeviceId> &result)
{
    int32_t size = data.ReadInt32();
    if (size > EdmConstants::ALLOWED_USB_DEVICES_MAX_SIZE) {
        EDMLOGE("ArrayUsbDeviceIdSerializer:GetPolicy size=[%{public}d] is too large", size);
        return false;
    }
    for (int32_t i = 0; i < size; i++) {
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
    return true;
}
} // namespace EDM
} // namespace OHOS