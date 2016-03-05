#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>

#include <freefare.h>
#include "auto_auth.h"

int main(int argc, char *argv[]) {

	// Init stuff
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;
    nfc_connstring devices[8];
    size_t device_count;

	// Init nfc context
    nfc_context *context;
    nfc_init (&context);
    if (context == NULL)
		errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

	// List devices
    device_count = nfc_list_devices (context, devices, 8);
    if (device_count <= 0)
	errx (EXIT_FAILURE, "No NFC device found.");

	// Iterate over devivces
    for (size_t d = 0; d < device_count; d++) {
		// Try to open devices
        device = nfc_open (context, devices[d]);
        if (!device) {
            warnx ("nfc_open() failed.");
            error = EXIT_FAILURE;
            continue;
        }

		// Try to get tags 
		tags = freefare_get_tags (device);
		if (!tags) {
			nfc_close (device);
			errx (EXIT_FAILURE, "Error listing tags.");
		}

		// Iterate over tags
		for (int i = 0; (!error) && tags[i]; i++) {

			// Skip everything witch is not desfire
			if (MIFARE_DESFIRE != freefare_get_tag_type (tags[i]))
			continue;

			int res;
			char *tag_uid = freefare_get_tag_uid (tags[i]);
			uint8_t key_version;
			MifareDESFireKey key = malloc(sizeof(MifareDESFireKey));

			// Try to connect to tag
			res = mifare_desfire_connect (tags[i]);
			if (res < 0) {
				warnx ("Can't connect to Mifare DESFire target.");
				error = 1;
				break;
			}else{
				printf("Connected uid: %s\n", tag_uid);
			}

			// Try to authenticate with a default key and store it
			mifare_desfire_get_key_version (tags[i], 0, &key_version);
			res = mifare_desfire_auto_authenticate(&key, tags[i], 0);
			mifare_desfire_key_free (key);


			if(res < 0){
				printf("Error while geting the master key.....\n"); 
				break;
			}

			// Create an application id (aid) and try to create a new application with it
			MifareDESFireAID aid = mifare_desfire_aid_new (0x112233);
			//res = mifare_desfire_create_application (tags[i], aid, 0xFF, 1);

			// Get all aids currently on the tag
			size_t count;
			MifareDESFireAID **aids = malloc(sizeof(MifareDESFireAID*)); 
			res = mifare_desfire_get_application_ids(tags[i], aids, &count);

			// Print all aids
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

