/*
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

// suricata headers
#include "suricata-plugin.h"
#include "util-mem.h"
#include "util-debug.h"
#include "util-print.h"

// For PrintInet
#include "util-print.h"

// suricata headers
#include "decode.h"
#include "output.h"
#include "output-filedata.h"

#include "plugin.h"
#include "debug.h"

#define TMP_FILEDIR "/tmp/filedata"
#define FILENAME_LEN 32


static TmEcode ThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    INSPECTOR_PLUGIN_DEBUG("threadInit");
    return TM_ECODE_OK;
}

static TmEcode ThreadDeinit(ThreadVars *tv, void *data)
{
    INSPECTOR_PLUGIN_DEBUG("threadDeinit");
    // Nothing to do. If we allocated data in ThreadInit we would free
    // it here.
    return TM_ECODE_OK;
}

// Function to generate a random filename
void genFilename(char* filename, size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // Seed the random number generator with the current time
    srand((unsigned int)time(NULL));

    for (size_t i = 0; i < length - 1; ++i) {
        filename[i] = charset[rand() % (sizeof(charset) - 1)];
    }

    filename[length - 1] = '\0';
}

static int FiledataLogFunc(ThreadVars *tv, void *thread_data, const Packet *p, File *ff, void *tx,
const uint64_t tx_id, const uint8_t *data, uint32_t data_len, uint8_t flags, uint8_t dir)
{
    SCEnter();
    //OutputFilestoreLogThread *aft = (OutputFilestoreLogThread *)thread_data;
    //
    char pathname[PATH_MAX] = "";
    char filename[FILENAME_LEN] = "";

    INSPECTOR_PLUGIN_INFO("find file: %s, len: %u", ff->name, data_len);
    //printf("file_store_id %s\n", ff->file_store_id);
    //printf("%x %x %x %x\n", data[0], data[1], data[2], data[3]);

    /*
    char sha256string[(SC_SHA256_LEN * 2) + 1];
    PrintHexString(sha256string, sizeof(sha256string), ff->sha256,
            sizeof(ff->sha256));
    */
    genFilename(filename, FILENAME_LEN);
    snprintf(pathname, sizeof(pathname), "%s/%s", TMP_FILEDIR, filename);
    INSPECTOR_PLUGIN_DEBUG("save to file %s", pathname);
    int file_fd = open(pathname, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
    if (file_fd == -1) {
        return -1;
    }
    ssize_t r = write(file_fd, (const void *)data, (size_t)data_len);
    if (r == -1) {
        INSPECTOR_PLUGIN_ERROR("write to file error: %d", r);
        return -1;
    }
    close(file_fd);

    // send to Bitdefender
    ScanFile(pathname);

    return 0;
}

static void InitFunc(void)
{
    INSPECTOR_PLUGIN_DEBUG("InitFunc");
    OutputRegisterFiledataLogger(LOGGER_FILEDATA, "custom-filedata-logger",
            FiledataLogFunc, NULL, ThreadInit, ThreadDeinit, NULL);

}

const SCPlugin PluginRegistration = {
    .name = "InspectorPlugin",
    .author = "Your Name",
    .license = "GPLv2",
    .Init = InitFunc,
};

const SCPlugin *SCPluginRegister()
{
    return &PluginRegistration;
}
