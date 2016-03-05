/*-
 * Copyright (C) 2010, Romain Tartiere.
 * 
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>

#include <freefare.h>

uint8_t key_data_null[8]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t key_data_des[8]   = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H' };
uint8_t key_data_3des[16] = { 'C', 'a', 'r', 'd', ' ', 'M', 'a', 's', 't', 'e', 'r', ' ', 'K', 'e', 'y', '!' };
uint8_t key_data_aes[16]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t key_data_3k3des[24]  = { 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

const uint8_t key_data_aes_version = 0x42;

int mifare_desfire_auto_authenticate (FreefareTag tag, uint8_t key_no, MifareDESFireKey key)
{
    /* Determine which key is currently the master one */
    uint8_t key_version;
    int res = mifare_desfire_get_key_version (tag, key_no, &key_version);

    printf("key_version: %x\n", key_version);
    switch (key_version) {
        case 0x00:
          key = mifare_desfire_des_key_new_with_version (key_data_null);
        break;
        case 0x42:
          key = mifare_desfire_aes_key_new_with_version (key_data_aes, key_data_aes_version);
        break;
        case 0xAA:
          key = mifare_desfire_des_key_new_with_version (key_data_des);
        break;
        case 0xC7:
          key = mifare_desfire_3des_key_new_with_version (key_data_3des);
        break;
        case 0x55:
          key = mifare_desfire_3k3des_key_new_with_version (key_data_3k3des);
        break;
    }

    /* Authenticate with this key */
    switch (key_version) {
        case 0x00:
        case 0xAA:
        case 0xC7:
            res = mifare_desfire_authenticate (tag, key_no, key);
        break;
        case 0x55:
            res = mifare_desfire_authenticate_iso (tag, key_no, key);
        break;
        case 0x42:
            res = mifare_desfire_authenticate_aes (tag, key_no, key);
        break;
    }

    return res;
}

int
main(int argc, char *argv[])
{
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;

    if (argc > 1)
	errx (EXIT_FAILURE, "usage: %s", argv[0]);

    nfc_connstring devices[8];
    size_t device_count;

    nfc_context *context;
    nfc_init (&context);
    if (context == NULL)
	errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

    device_count = nfc_list_devices (context, devices, 8);
    if (device_count <= 0)
	errx (EXIT_FAILURE, "No NFC device found.");

    for (size_t d = 0; d < device_count; d++) {
        device = nfc_open (context, devices[d]);
        if (!device) {
            warnx ("nfc_open() failed.");
            error = EXIT_FAILURE;
            continue;
        }

	tags = freefare_get_tags (device);
	if (!tags) {
	    nfc_close (device);
	    errx (EXIT_FAILURE, "Error listing tags.");
	}

	for (int i = 0; (!error) && tags[i]; i++) {

	    if (MIFARE_DESFIRE != freefare_get_tag_type (tags[i]))
		continue;

	    int res;
	    char *tag_uid = freefare_get_tag_uid (tags[i]);

	    res = mifare_desfire_connect (tags[i]);
	    if (res < 0) {
            warnx ("Can't connect to Mifare DESFire target.");
            error = 1;
            break;
	    }else{
            printf("Connected uid: %s\n", tag_uid);
        }

        uint8_t key_version;
        mifare_desfire_get_key_version (tags[i], 0, &key_version);
        MifareDESFireKey key = malloc(sizeof(MifareDESFireKey));

        res = mifare_desfire_auto_authenticate(tags[i], 0, key);

        if(res < 0){
            printf("Error while geting the master key.....\n"); 
            break;
        }

        MifareDESFireAID aid = mifare_desfire_aid_new (0x112233);
		//res = mifare_desfire_create_application (tags[i], aid, 0xFF, 1);

        size_t count;
        MifareDESFireAID **aids = malloc(sizeof(MifareDESFireAID*)); 
        res = mifare_desfire_get_application_ids(tags[i], aids, &count);

        if(res==0){
            printf("found %d applicaton/s\n", (int)count);
            //struct MifareDESFireAID aidArr[count] = *aids;
            int j;
            for(j=0; j<count; j++){
                // Fails here
                aid = (*aids)[j];
                printf("aid %d: %x\n", j, mifare_desfire_aid_get_aid(aid));

                if(mifare_desfire_aid_get_aid(aid) == 0x112233){
                    if(mifare_desfire_select_application(tags[i], aid) == 0){ 
                      printf("app selected...\n");
                      size_t fileCount = 0;
                      uint8_t **files = malloc(sizeof(uint8_t));
                      int rra = mifare_desfire_get_file_ids(tags[i], files, &fileCount);
                      printf("%d found %d file ids\n", rra, (int)fileCount);
                    }
                }

            }
            printf("ok\n");
        }else{
            printf("error res is %d\n", res);
        }
        
        mifare_desfire_key_free (key);

	    free (tag_uid);

	    mifare_desfire_disconnect (tags[i]);
	}

	freefare_free_tags (tags);
	nfc_close (device);
    }
    nfc_exit (context);
    exit (error);
} /* main() */

