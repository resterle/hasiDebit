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

void cleanup(nfc_context *context, nfc_device *device, FreefareTag *tag){
    if(tag)
	    mifare_desfire_disconnect(*tag);
    if(device)
	    nfc_close(device);
    nfc_exit (context);
}

void finalize_error(FreefareTag* tag, nfc_device *device, nfc_context* context, char message[]){
    cleanup(context, device, tag);
	err(EXIT_FAILURE, message);
}

void get_tag(nfc_context* context, FreefareTag* tag){
	
    nfc_connstring devices[8];
    size_t device_count;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;

	// List devices
    device_count = nfc_list_devices (context, devices, 8);
    if (device_count <= 0)
		errx(EXIT_FAILURE, "No NFC device found.");
	if (device_count > 1)
		errx(EXIT_FAILURE, "Only one connected device is sopported");

	// Open device
	device = nfc_open(context, devices[0]);
	if (!device) {
		errx (EXIT_FAILURE, "nfc_open() failed.");
	}

	// Try to get tag 
	tags = freefare_get_tags (device);
	if (!tags)
        finalize_error(NULL, device, context, "Error listing tags.");

	if(!tags[0])
        finalize_error(NULL, device, context, "No tag detected.");
	if(tags[1]){
        finalize_error(NULL, device, context, "More than one tag detected");
    }

	*tag = tags[0];
    // Check if tag is a desfire tag
	if (MIFARE_DESFIRE != freefare_get_tag_type (*tag))
        finalize_error(NULL, device, context, "Tag is not a desfire tag");

	// Try to connect to tag
	if(mifare_desfire_connect(*tag) != 0)
        finalize_error(NULL, device, context, "Cannot connect to tag");
}

int get_default_key(FreefareTag tag, uint8_t key_no){

	// Try to authenticate with a default key and store it
	if(mifare_desfire_auto_authenticate(tag, key_no) != 0){
        return 1;
        // TODO error handling 
		printf("Cannot get dafault key for uid: \n");
	} 
    return 0;
}

int get_application_ids(FreefareTag tag, MifareDESFireAID** aids, size_t* count){
	mifare_desfire_get_application_ids(tag, aids, count);
}

int get_files(FreefareTag tag, MifareDESFireAID aid, uint8_t* file_ids, size_t* count){
	if(mifare_desfire_select_application(tag, aid) != 0)
		return 1;
	if(mifare_desfire_get_file_ids(tag, &file_ids, count) != 0)
		return 1;
	return 0;
}

int main(int argc, char *argv[]) {

	nfc_context* context;
	init_nfc(&context);

	FreefareTag tag;
	get_tag(context, &tag);

	char *tag_uid = freefare_get_tag_uid (tag);

	// Create an application id (aid) and try to create a new application with it
	MifareDESFireAID aid = mifare_desfire_aid_new (0x112233);
	//res = mifare_desfire_create_application (tags[i], aid, 0xFF, 1);

	// Get all aids currently on the tag
	size_t count;
	MifareDESFireAID* aids = malloc(sizeof(MifareDESFireAID)); 
	get_application_ids(tag, &aids, &count);

	printf("found %d applicaton/s\n", (int)count);

	int i,j;
	for(i=0; i<count; i++){
		aid = aids[i];
		printf("aid %d: %x\n", i, mifare_desfire_aid_get_aid(aid));

		size_t count2;
		uint8_t *file_ids = malloc(sizeof(uint8_t));

		// Get files for aid
		if(get_files(tag, aid, file_ids, &count2) != 0)
			continue;
		printf("found %d file ids\n", (int)count2);

		for(j=0; j<count2; j++){
			printf("	File id: %x ", file_ids[j]);
			struct mifare_desfire_file_settings settings;
			mifare_desfire_get_file_settings (tag, file_ids[j], &settings);
			printf("  Type: %x", settings.file_type);
			printf("  com settings: %x", settings.communication_settings);
			printf("  standard f size: %x", settings.settings.standard_file.file_size); 
			printf("  access: %x\n", settings.access_rights);
		}

	}
    return 0;
}
