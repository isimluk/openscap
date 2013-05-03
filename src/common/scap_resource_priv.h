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

#ifndef OSCAP_SCAP_RESOURCE_PRIV_H_
#define OSCAP_SCAP_RESOURCE_PRIV_H_

#include "public/scap_resource.h"
#include <libxml/tree.h>
#include <libxml/xmlreader.h>

struct scap_resource *scap_resource_from_xmlnode(xmlDocPtr doc, xmlNodePtr node);

xmlDocPtr scap_resource_get_xmldoc(struct scap_resource *resource);
xmlNodePtr scap_resource_get_xmlnode(struct scap_resource *resource);

/**
 * Creates a xmlTextReader that is set to read from the beginning of the resource
 *
 * The caller is responsible for deallocating the returned reader!
 */
xmlTextReaderPtr scap_resource_wrap_as_xmltextreader(struct scap_resource *resource);

#endif
