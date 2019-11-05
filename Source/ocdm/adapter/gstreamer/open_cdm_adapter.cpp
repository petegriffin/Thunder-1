
#include "open_cdm_adapter.h"

#include <gst/gst.h>
#include <gst/base/gstbytereader.h>
#include <gst/allocators/gstdmabuf.h>

#define ENABLE_SECURE_DATA_PATH 1

OpenCDMError opencdm_gstreamer_session_decrypt(struct OpenCDMSession* session, GstBuffer* buffer, GstBuffer* subSampleBuffer, const uint32_t subSampleCount,
                                               GstBuffer* IV, GstBuffer* keyID, uint32_t initWithLast15, GstBuffer* decBuffer)
{
    OpenCDMError result (ERROR_INVALID_SESSION);

#ifdef ENABLE_SECURE_DATA_PATH
    uint32_t *subSampleMapping = nullptr;
    gint secureFd = -1;
    uint32_t secureSize = 0;
    gboolean secure = FALSE;
#endif

    if (session != nullptr) {
        GstMapInfo dataMap;
        if (gst_buffer_map(buffer, &dataMap, (GstMapFlags) GST_MAP_READ) == false) {
            printf("Invalid buffer.\n");
            return (ERROR_INVALID_DECRYPT_BUFFER);
        }

        GstMapInfo ivMap;
        if (gst_buffer_map(IV, &ivMap, (GstMapFlags) GST_MAP_READ) == false) {
            gst_buffer_unmap(buffer, &dataMap);
            printf("Invalid IV buffer.\n");
            return (ERROR_INVALID_DECRYPT_BUFFER);
        }

        uint8_t *mappedKeyID = nullptr;
        uint32_t mappedKeyIDSize = 0;

        GstMapInfo keyIDMap;
        if (keyID != nullptr) {
           if (gst_buffer_map(keyID, &keyIDMap, (GstMapFlags) GST_MAP_READ) == false) {
               gst_buffer_unmap(buffer, &dataMap);
               gst_buffer_unmap(IV, &ivMap);
               printf("Invalid keyID buffer.\n");
               return (ERROR_INVALID_DECRYPT_BUFFER);
           }

           mappedKeyID = reinterpret_cast<uint8_t* >(keyIDMap.data);
           mappedKeyIDSize =  static_cast<uint32_t >(keyIDMap.size);
        }

        uint8_t *mappedData = reinterpret_cast<uint8_t* >(dataMap.data);
        uint32_t mappedDataSize = static_cast<uint32_t >(dataMap.size);
        uint8_t *mappedIV = reinterpret_cast<uint8_t* >(ivMap.data);
        uint32_t mappedIVSize = static_cast<uint32_t >(ivMap.size);

#ifdef ENABLE_SECURE_DATA_PATH
        GstMapInfo decMap;

        if (gst_buffer_map(decBuffer, &decMap, static_cast<GstMapFlags>(GST_MAP_READWRITE)) == false) {
            gst_buffer_unmap(buffer, &dataMap);
            gst_buffer_unmap(IV, &ivMap);
            gst_buffer_unmap(keyID, &keyIDMap);
            printf("Invalid decrypted buffer.\n");
            return (ERROR_INVALID_DECRYPT_BUFFER);
        }

        uint8_t *mappedDecData = reinterpret_cast<uint8_t* >(decMap.data);
        uint32_t mappedDecDataSize = static_cast<uint32_t >(decMap.size);

        // Copy source data to mapped memory (shared memory used for the metadata).
        // For non-secure content, copy the data and perform the decryption in-place.
        // TODO: Secure: Copy only the clear data
        //       Non-secure: Copy everything to perform decryption in-place
        memcpy(mappedDecData, mappedData, mappedDataSize);

        // Retrieve secure ION file descriptor
        if(gst_buffer_n_memory(decBuffer) != 1) {
            printf("WARNING: Decrypted GstBuffer does not have exactly one GstMemory block\n");
        }
        GstMemory *decMem = gst_buffer_get_memory(decBuffer, 0);
        {
            const gchar *mem_type = decMem->allocator->mem_type;

            if(g_strcmp0(mem_type, "ionmem") == 0) {
                secureFd = gst_dmabuf_memory_get_fd(decMem);
                gsize offset = 0;
                gsize maxSize = 0;
                secureSize = gst_memory_get_sizes (decMem, &offset, &maxSize);
                secure = TRUE;
            } else {
                secureFd = -1;
                secureSize = 0;
                secure = FALSE;
            }
        }
#endif

        if (subSampleBuffer != nullptr) {
            GstMapInfo sampleMap;
            if (gst_buffer_map(subSampleBuffer, &sampleMap, GST_MAP_READ) == false) {
                printf("Invalid subsample buffer.\n");
                if (keyID != nullptr) {
                   gst_buffer_unmap(keyID, &keyIDMap);
                }
                gst_buffer_unmap(IV, &ivMap);
                gst_buffer_unmap(buffer, &dataMap);
                return (ERROR_INVALID_DECRYPT_BUFFER);
            }

#ifdef ENABLE_SECURE_DATA_PATH
            subSampleMapping = (uint32_t *)malloc(2 * subSampleCount * sizeof(uint32_t));
            if (subSampleMapping == nullptr) {
                printf("Failed to allocate memory for the sub-sample mapping\n");
                // TODO: More cleaning is required
                gst_buffer_unmap(subSampleBuffer, &sampleMap);
                return (ERROR_INVALID_DECRYPT_BUFFER);
            }
#endif

            uint8_t *mappedSubSample = reinterpret_cast<uint8_t* >(sampleMap.data);
            uint32_t mappedSubSampleSize = static_cast<uint32_t >(sampleMap.size);
            GstByteReader* reader = gst_byte_reader_new(mappedSubSample, mappedSubSampleSize);
            uint16_t inClear = 0;
            uint32_t inEncrypted = 0;
            uint32_t totalEncrypted = 0;
            for (unsigned int position = 0; position < subSampleCount; position++) {
                uint32_t offset = 0;

                gst_byte_reader_get_uint16_be(reader, &inClear);
                gst_byte_reader_get_uint32_be(reader, &inEncrypted);
                totalEncrypted += inEncrypted;

#ifdef ENABLE_SECURE_DATA_PATH
                // Format the sub-sample mapping as an array of interleaved clear and encrypted data size. 
                subSampleMapping[2 * position]     = inClear;
                subSampleMapping[2 * position + 1] = inEncrypted;

                // TODO For the secure content, trying to clear the encrypted content from the shared memory
#if 0
                // TODO: Restore this code
                if(secure) {
                    offset += inClear;
                    memset(mappedDecData + offset, 0, inEncrypted);
                    offset += inEncrypted;
                }
#endif
#endif
            }
            gst_byte_reader_set_pos(reader, 0);

#ifndef ENABLE_SECURE_DATA_PATH
            uint8_t* encryptedData = reinterpret_cast<uint8_t*> (malloc(totalEncrypted));
            uint8_t* encryptedDataIter = encryptedData;

            uint32_t index = 0;
            for (unsigned int position = 0; position < subSampleCount; position++) {

                gst_byte_reader_get_uint16_be(reader, &inClear);
                gst_byte_reader_get_uint32_be(reader, &inEncrypted);

                memcpy(encryptedDataIter, mappedData + index + inClear, inEncrypted);

                index += inClear + inEncrypted;
                encryptedDataIter += inEncrypted;
            }
            gst_byte_reader_set_pos(reader, 0);

            result = opencdm_session_decrypt(session, encryptedData, totalEncrypted, mappedIV, mappedIVSize, mappedKeyID, mappedKeyIDSize, initWithLast15/*, NULL, 0, -1, 0*/);

            // Re-build sub-sample data.
            index = 0;
            unsigned total = 0;
            for (uint32_t position = 0; position < subSampleCount; position++) {
                gst_byte_reader_get_uint16_be(reader, &inClear);
                gst_byte_reader_get_uint32_be(reader, &inEncrypted);

                memcpy(mappedData + total + inClear, encryptedData + index, inEncrypted);

                index += inEncrypted;
                total += inClear + inEncrypted;
            }

            free(encryptedData);
#else
            // TODO: Secure/non-secure may share the same call. It depends on the source buffer.
            if(secure) {
                result = opencdm_session_decrypt(session, mappedData, mappedDataSize, mappedIV, mappedIVSize, mappedKeyID, mappedKeyIDSize, initWithLast15, subSampleMapping, (2 * subSampleCount), secureFd, secureSize);
            } else {
                result = opencdm_session_decrypt(session, mappedDecData, mappedDecDataSize, mappedIV, mappedIVSize, mappedKeyID, mappedKeyIDSize, initWithLast15, subSampleMapping, (2 * subSampleCount), -1, 0);
                printf("WARNING: Ignore error in opencdm_session_decrypt (non-secure) \n");
                result = ERROR_NONE;
            }
#endif

            gst_byte_reader_free(reader);
            gst_buffer_unmap(subSampleBuffer, &sampleMap);
        } else {
#ifdef ENABLE_SECURE_DATA_PATH
            if(secure) {
                result = opencdm_session_decrypt(session, mappedData, mappedDataSize, mappedIV, mappedIVSize, mappedKeyID, mappedKeyIDSize, initWithLast15, NULL, 0, secureFd, secureSize);
            } else {
                result = opencdm_session_decrypt(session, mappedDecData, mappedDecDataSize, mappedIV, mappedIVSize, mappedKeyID, mappedKeyIDSize, initWithLast15, NULL, 0, -1, 0);
                /*if(result != ERROR_NONE) {
                    printf("WARNING: Ignore error in opencdm_session_decrypt (non-secure) \n");
                    result = ERROR_NONE;
                }*/
            }
#else
            result = opencdm_session_decrypt(session, mappedData, mappedDataSize,  mappedIV, mappedIVSize, mappedKeyID, mappedKeyIDSize, initWithLast15/*, NULL, 0, -1, 0*/);
#endif            
        }

        if (keyID != nullptr) {
           gst_buffer_unmap(keyID, &keyIDMap);
        }

        gst_buffer_unmap(IV, &ivMap);
        gst_buffer_unmap(buffer, &dataMap);
#ifdef ENABLE_SECURE_DATA_PATH
        if(decMem) gst_memory_unref(decMem);
        gst_buffer_unmap(decBuffer, &decMap);
        if(subSampleMapping != nullptr) {
            free(subSampleMapping);
        }
#endif
    }

    return (result);
}
