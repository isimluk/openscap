/*
 * Copyright 2013 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Martin Preisler <mpreisle@redhat.com>
 */

#ifndef OSCAP_SCAP_RESOURCE_H_
#define OSCAP_SCAP_RESOURCE_H_

#include "oscap.h"

struct scap_resource;

struct scap_resource *scap_resource_from_file(const char *path);

void scap_resource_free(struct scap_resource *resource);

//int scap_resource_get_document_type(struct scap_resource *resource);
//bool scap_resource_validate(struct scap_resource *resource);

const char *scap_resource_get_contents(struct scap_resource *resource);

/**
 * Creates a file and write resource's data to it
 *
 * @param path Path to the target file, if NULL is given a temporary file is created instead.
 * The caller is responsible for deleting the file after use!
 */
int scap_resource_save_to_file(struct scap_resource *resource, const char *path);

#endif
