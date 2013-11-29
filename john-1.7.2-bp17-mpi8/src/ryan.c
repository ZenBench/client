#include "mpi.h"
//#include "ryan.h"
#include <stdio.h>
#include <string.h>

int mpi_p, mpi_id;

/* Fixed version of id2string to correct a memory leak
 * Submitted by Carsten G
 */
char *id2string() {
        static char id_string[12] = "";
        if (strlen(id_string)) return id_string;
        snprintf(id_string, 11, "%d", mpi_id);
        id_string[11] = 0x00;
        return id_string;
}
