#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>

#include <freefare.h>
#include "auto_auth.h"

int init_nfc(nfc_context** context) {
    nfc_init (context);
    if (context == NULL)
		errx(EXIT_FAILURE, "Unable to init context");
}



int get_tag(nfc_context* context, FreefareTag* tag){
	
    nfc_connstring devices[8];
    size_t device_count;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;

	// List devices
    device_count = nfc_list_devices (context, devices, 8);
    if (device_count <= 0)
		err(EXIT_FAILURE, "No NFC device found.");
	if (device_count > 1)
		err(EXIT_FAILURE, "Only one connected device is sopported");

	// Open device
	device = nfc_open(context, devices[0]);
	if (!device) {
		errx (EXIT_FAILURE, "nfc_open() failed.");
	}

	// Try to get tag 
	tags = freefare_get_tags (device);
	if (!tags) {
		nfc_close (device);
		errx (EXIT_FAILURE, "Error listing tags.");
	}

	if(tags[1])
		errx (EXIT_FAILURE, "More than one tag detected");

	*tag = tags[0];
	if (MIFARE_DESFIRE != freefare_get_tag_type (*tag))
		errx (EXIT_FAILURE, "Tag is not a desfire tag");

	// Try to connect to tag
	if(mifare_desfire_connect(*tag) != 0)
		errx (EXIT_FAILURE, "Cannot connect to tag");
}


int main(int argc, char *argv[]) {

	nfc_context* context;
	init_nfc(&context);

	FreefareTag tag;
	get_tag(context, &tag);

	char *tag_uid = freefare_get_tag_uid (tag);
	uint8_t key_version;
	MifareDESFireKey key = malloc(sizeof(MifareDESFireKey));

	// Try to authenticate with a default key and store it
	mifare_desfire_get_key_version (tag, 0, &key_version);
	int res = mifare_desfire_auto_authenticate(&key, tag, 0);
	mifare_desfire_key_free (key);

	if(res < 0){
		printf("Error while geting the master key.....\n"); 
	}

	// Create an application id (aid) and try to create a new application with it
	MifareDESFireAID aid = mifare_desfire_aid_new (0x112233);
	//res = mifare_desfire_create_application (tags[i], aid, 0xFF, 1);

	// Get all aids currently on the tag
	size_t count;
	MifareDESFireAID **aids = malloc(sizeof(MifareDESFireAID*)); 
	res = mifare_desfire_get_application_ids(tag, aids, &count);

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
				if(mifare_desfire_select_application(tag, aid) == 0){ 
				  printf("app selected...\n");
				  size_t fileCount = 0;
				  uint8_t **files = malloc(sizeof(uint8_t));
				  int rra = mifare_desfire_get_file_ids(tag, files, &fileCount);
				  printf("%d found %d file ids\n", rra, (int)fileCount);
				}
			}

		}
	}else{
		printf("error res is %d\n", res);
	}
			
	mifare_desfire_key_free (key);

	mifare_desfire_disconnect(tag);
	//nfc_close (device);
    nfc_exit (context);
} /* main() */

