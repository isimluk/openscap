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
 *       Martin Preisler <mpreisle@redhat.com>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "scap_resource_priv.h"
#include "common/_error.h"
#include "common/alloc.h"
#include "common/util.h"

enum scap_resource_origin
{
	SRO_INVALID = -1,

	SRO_FILE = 1,
	SRO_MEMORY_BUFFER = 2,
	SRO_DOM = 3
};

struct scap_resource
{
	/// Where is the authoritative source for this scap_resource
	int origin;

	/// From where have we loaded the resource, can be NULL if resource is not from a file
	char *file_path;
	/// Contents in a \0 terminated buffer, can be NULL and is lazy filled
	char *contents;
	/// Preparsed document representing the resource, can be NULL and is lazy parsed
	xmlDocPtr dom;
};

static struct scap_resource *scap_resource_new(void)
{
	struct scap_resource *ret = (struct scap_resource *)oscap_calloc(1, sizeof(struct scap_resource));
	ret->origin = SRO_INVALID;
	return ret;
}

struct scap_resource *scap_resource_from_file(const char *path)
{
	struct scap_resource *ret = scap_resource_new();
	ret->origin = SRO_FILE;
	ret->file_path = oscap_strdup(path);

	return ret;
}

struct scap_resource *scap_resource_from_xmlnode(xmlDocPtr doc, xmlNodePtr node)
{
	struct scap_resource *ret = scap_resource_new();
	ret->origin = SRO_DOM;

	xmlDOMWrapCtxtPtr wrap_ctxt = xmlDOMWrapNewCtxt();

	ret->dom = xmlNewDoc(BAD_CAST "1.0");
	xmlNodePtr res_node = NULL;
	if (xmlDOMWrapCloneNode(wrap_ctxt, doc, node, &res_node, ret->dom, NULL, 1, 0) != 0) {
		oscap_seterr(OSCAP_EFAMILY_XML, "Error when cloning node for scap_resource.");
		xmlFreeDoc(ret->dom);
		ret->dom = NULL;
		scap_resource_free(ret);
		xmlDOMWrapFreeCtxt(wrap_ctxt);
		return NULL;
	}
	xmlDocSetRootElement(ret->dom, res_node);
	if (xmlDOMWrapReconcileNamespaces(wrap_ctxt, res_node, 0) != 0) {
		oscap_seterr(OSCAP_EFAMILY_XML, "Internal libxml error when reconciling namespaces while cloning node for scap_resource.");
		xmlFreeDoc(ret->dom);
		ret->dom = NULL;
		scap_resource_free(ret);
		xmlDOMWrapFreeCtxt(wrap_ctxt);
		return NULL;
	}

	xmlDOMWrapFreeCtxt(wrap_ctxt);

	return ret;
}

void scap_resource_free(struct scap_resource *resource)
{
	if (resource) {
		if (resource->file_path)
			oscap_free(resource->file_path);
		if (resource->contents)
			oscap_free(resource->contents);
		if (resource->dom)
			xmlFreeDoc(resource->dom);

		oscap_free(resource);
	}
}

//int scap_resource_get_document_type(struct scap_resource *resource);
//bool scap_resource_validate(struct scap_resource *resource);

const char *scap_resource_get_contents(struct scap_resource *resource)
{
	if (resource->origin == SRO_FILE) {
		if (resource->contents) // use cached value if available
			return resource->contents;

		FILE *fp = fopen(resource->file_path, "r");
		if (fp == NULL) {
			oscap_seterr(OSCAP_EFAMILY_GLIBC, "Can't open file '%s' in scap_resource.", resource->file_path);
			return NULL;
		}
		if (fseek(fp, 0L, SEEK_END) != 0) {
			oscap_seterr(OSCAP_EFAMILY_GLIBC, "Can't seek to the end of file '%s'.", resource->file_path);
			fclose(fp);
			return NULL;
		}

		const long buffer_size = ftell(fp);
		if (buffer_size == -1) {
			oscap_seterr(OSCAP_EFAMILY_GLIBC, "Unable to determine content size of file '%s'.", resource->file_path);
			fclose(fp);
			return NULL;
		}

		resource->contents = oscap_alloc(sizeof(char) * (buffer_size + 1)); // +1 for \0

		if (fseek(fp, 0L, SEEK_SET) == 0) {
			oscap_seterr(OSCAP_EFAMILY_GLIBC, "Unable to rewind file '%s' to the beginning.", resource->file_path);
			oscap_free(resource->contents);
			resource->contents = NULL;
			fclose(fp);
			return NULL;
		}

		const size_t read_bytes = fread(resource->contents, sizeof(char), buffer_size, fp);
		if (read_bytes == 0) {
			oscap_seterr(OSCAP_EFAMILY_GLIBC, "Can't read contents of file '%s'.", resource->file_path);
			oscap_free(resource->contents);
			resource->contents = NULL;
			fclose(fp);
			return NULL;
		} else {
			resource->contents[read_bytes] = '\0';
		}

		fclose(fp);

		return resource->contents;
	}
	else if (resource->origin == SRO_MEMORY_BUFFER) {
		return resource->contents;
	}
	else if (resource->origin == SRO_DOM) {
		if (resource->contents) // use cached value if available
			return resource->contents;

		xmlChar* buffer;
		int buffer_len;

		xmlDocDumpMemory(resource->dom, &buffer, &buffer_len);
		// NB: We don't use the buffer_len, according to libxml2 docs
		//     the buffer is \0 terminated.
		resource->contents = (char*)buffer;
		return resource->contents;
	}
	else if (resource->origin == SRO_INVALID) {
		oscap_seterr(OSCAP_EFAMILY_GLIBC, "scap_resource's origin is invalid, can't return its contents!");
		return NULL;
	}
	else {
		oscap_seterr(OSCAP_EFAMILY_GLIBC, "scap_resource's origin is '%i' which is an unknown value!", resource->origin);
		return NULL;
	}
}

xmlDocPtr scap_resource_get_xmldoc(struct scap_resource *resource)
{
	if (resource->origin == SRO_FILE) {
		if (resource->dom) // use cached value if available
			return resource->dom;

		resource->dom = xmlReadFile(resource->file_path, NULL, 0);
		if (!resource->dom) {
			oscap_setxmlerr(xmlGetLastError());
			return NULL;
		}

		return resource->dom;
	}
	else if (resource->origin == SRO_DOM) {
		return resource->dom;
	}
	else if (resource->origin == SRO_MEMORY_BUFFER) {
		if (resource->dom) // use cached value if available
			return resource->dom;

		resource->dom = xmlReadDoc(BAD_CAST resource->contents, NULL, NULL, 0);
		return resource->dom;
	}
	else if (resource->origin == SRO_INVALID) {
		oscap_seterr(OSCAP_EFAMILY_GLIBC, "scap_resource's origin is invalid, can't return its DOM!");
		return NULL;
	}
	else {
		oscap_seterr(OSCAP_EFAMILY_GLIBC, "scap_resource's origin is '%i' which is an unknown value!", resource->origin);
		return NULL;
	}
}

xmlNodePtr scap_resource_get_xmlnode(struct scap_resource *resource)
{
	xmlDocPtr doc = scap_resource_get_xmldoc(resource);
	// if doc is NULL the error is already set
	return doc == NULL ? NULL : xmlDocGetRootElement(doc);
}

xmlTextReaderPtr scap_resource_wrap_as_xmltextreader(struct scap_resource *resource)
{
	xmlDocPtr doc = scap_resource_get_xmldoc(resource);
	if (!doc)
		return NULL; // error is already set

	return xmlReaderWalker(doc);
}

int scap_resource_save_to_file(struct scap_resource *resource, const char *path)
{
	const char *contents = scap_resource_get_contents(resource);

	FILE *fp = fopen(resource->file_path, "r");
	// TODO: This is doing more work than it could, use fwrite instead
	fprintf(fp, "%s", contents);
	fclose(fp);

	return 0;
}
