#include "dr_api.h"

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
	(void)id;
	(void)argc;
	(void)argv;
	dr_abort_with_code(0);
}
