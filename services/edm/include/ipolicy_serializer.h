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

#ifndef SERVICES_EDM_INCLUDE_EDM_IPOLICY_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_EDM_IPOLICY_SERIALIZER_H

#include <algorithm>
#include <message_parcel.h>
#include <set>
#include <string>
#include <edm_log.h>
#include <string_ex.h>
#include "json/json.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
/*
 * Policy data serialize interface
 *
 * @tparam DT policy data type,like vector,map,int...
 */
template<class DT>
class IPolicySerializer {
public:
    /*
     * Deserialize a JSON string into a DT object.
     *
     * @param jsonString JSON string
     * @param dataObj DT object
     * @return true indicates that the operation is successful.
     */
    virtual bool Deserialize(const std::string &jsonString, DT &dataObj) = 0;

    /*
     * Serializes a DT object into a JSON string.
     *
     * @param dataObj DT object
     * @param jsonString JSON string
     * @return true indicates that the operation is successful.
     */
    virtual bool Serialize(const DT &dataObj, std::string &jsonString) = 0;

    /*
     * Obtains DT object data from the MessageParcel object.
     *
     * @param reply MessageParcel
     * @param result DT object
     * @return true indicates that the operation is successful.
     */
    virtual bool GetPolicy(MessageParcel &data, DT &result) = 0;

    /*
     * Write DT object data to MessageParcel
     *
     * @param reply MessageParcel
     * @param result DT object
     * @return true indicates that the operation is successful.
     */
    virtual bool WritePolicy(MessageParcel &reply, DT &result) = 0;

    /*
     * Obtain the final data from all DT data set by the admin.
     *
     * @param adminValuesArray DT data collection
     * @param result The end result
     * @return true indicates that the operation is successful.
     */
    virtual bool MergePolicy(std::vector<DT> &adminValuesArray, DT &result) = 0;

    virtual ~IPolicySerializer() = default;
};

/*
 * Policy data serialize interface
 *
 * @tparam DT policy data type in vector.
 * @tparam T_ARRAY policy data type,like vector<string>,vector<map>...
 */
template<typename DT, typename T_ARRAY = std::vector<DT>>
class ArraySerializer : public IPolicySerializer<T_ARRAY> {
public:
    virtual bool Deserialize(const std::string &jsonString, T_ARRAY &dataObj) override;

    virtual bool Serialize(const T_ARRAY &dataObj, std::string &jsonString) override;

    virtual bool GetPolicy(MessageParcel &data, T_ARRAY &result) override;

    virtual bool WritePolicy(MessageParcel &reply, T_ARRAY &result) override;

    virtual bool MergePolicy(std::vector<T_ARRAY> &data, T_ARRAY &result) override;

protected:
    std::shared_ptr<IPolicySerializer<DT>> serializerInner_;
};

template<typename DT, typename T_ARRAY>
bool ArraySerializer<DT, T_ARRAY>::Deserialize(const std::string &jsonString, T_ARRAY &dataObj)
{
    if (jsonString.empty()) {
        return true;
    }
    Json::Value root;
    const auto rawJsonLength = static_cast<int>(jsonString.length());
    JSONCPP_STRING err;
    Json::CharReaderBuilder builder;
    const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    if (!reader->parse(jsonString.c_str(), jsonString.c_str() + rawJsonLength, &root, &err)) {
        EDMLOGE("ArraySerializer Deserialize json to vector error. %{public}s ", err.c_str());
        return false;
    }
    if (!root.isArray()) {
        return false;
    }
    dataObj = std::vector<DT>(root.size());
    for (std::uint32_t i = 0; i < root.size(); ++i) {
        Json::StreamWriterBuilder writerBuilder;
        const std::string valueJsonString = Json::writeString(writerBuilder, root[i]);
        DT value;
        if (!serializerInner_->Deserialize(valueJsonString, value)) {
            return false;
        }
        dataObj.at(i) = value;
    }
    return true;
}

template<typename DT, typename T_ARRAY>
bool ArraySerializer<DT, T_ARRAY>::Serialize(const T_ARRAY &dataObj, std::string &jsonString)
{
    if (dataObj.empty()) {
        jsonString = "";
        return true;
    }
    Json::Value arrayData(Json::arrayValue);
    for (std::uint32_t i = 0; i < dataObj.size(); ++i) {
        std::string itemJson;
        DT item = dataObj.at(i);
        if (!serializerInner_->Serialize(item, itemJson)) {
            return false;
        }
        arrayData[i] = itemJson;
    }
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "    ";
    jsonString = Json::writeString(builder, arrayData);
    return true;
}

template<typename DT, typename T_ARRAY>
bool ArraySerializer<DT, T_ARRAY>::GetPolicy(MessageParcel &data, T_ARRAY &result)
{
    std::vector<std::u16string> readVector16;
    if (!data.ReadString16Vector(&readVector16)) {
        return false;
    }
    std::vector<std::string> readVector;
    if (!readVector16.empty()) {
        for (const auto &str16 : readVector16) {
            readVector.push_back(Str16ToStr8(str16));
        }
    }
    // Data will be appended to result, and the original data of result will not be deleted.
    for (const auto &itemJson : readVector) {
        DT item;
        if (!itemJson.empty()) {
            if (!serializerInner_->Deserialize(itemJson, item)) {
                return false;
            }
            result.push_back(item);
        }
    }
    return true;
}

template<typename DT, typename T_ARRAY>
bool ArraySerializer<DT, T_ARRAY>::WritePolicy(MessageParcel &reply, T_ARRAY &result)
{
    std::vector<std::u16string> writeVector;
    for (const auto &item : result) {
        std::string itemJson;
        if (!serializerInner_->Serialize(item, itemJson)) {
            return false;
        }
        writeVector.push_back(Str8ToStr16(itemJson));
    }
    return reply.WriteString16Vector(writeVector);
}

template<typename DT, typename T_ARRAY>
bool ArraySerializer<DT, T_ARRAY>::MergePolicy(std::vector<T_ARRAY> &data, T_ARRAY &result)
{
    std::set<DT> stData;
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

#endif // SERVICES_EDM_INCLUDE_EDM_IPOLICY_SERIALIZER_H
