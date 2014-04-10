/*
   p0f - API query code
   --------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#define _FROM_API

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tcp.h"
#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"
#include "p0f.h"
#include "api.h"
#include "process.h"
#include "readfp.h"

/* Process API queries. */

inline uint32_t ip_to_uint(const u8 *ip) {
  return (ip[0] << 24 | ip[1] << 16 | ip[2] << 8  | ip[3]);
}

int ip_in_network(const u8 *ip, const u8 *net, u8 prefix) {
  uint32_t mask      = (0xffffffff >> (32 - prefix)) << (32 - prefix);
  uint32_t ip_addr   = ip_to_uint(ip);
  uint32_t net_addr  = ip_to_uint(net);
  uint32_t net_lower = (net_addr & mask);
  uint32_t net_upper = (net_lower | (~mask));

  if (ip_addr >= net_lower && ip_addr <= net_upper) {
    return 1;
  }
  return 0;
}

void fill_host(struct p0f_api_response_host *r, struct host_data *h)
{
  if (!h || !r) {
    WARN("Something gone wrong\n");
    return;
  }

  strncpy((char *)r->addr, (char *)h->addr, 16);
  r->addr_type = h->ip_ver;
  r->first_seen = h->first_seen;
  r->last_seen  = h->last_seen;
  r->total_conn = h->total_conn;

  if (h->last_name_id != -1) {

    strncpy((char*)r->os_name, (char*)fp_os_names[h->last_name_id],
            P0F_STR_MAX + 1);

    if (h->last_flavor)
       strncpy((char*)r->os_flavor, (char*)h->last_flavor, P0F_STR_MAX + 1);

  }

  if (h->http_name_id != -1) {

    strncpy((char*)r->http_name, (char*)fp_os_names[h->http_name_id],
            P0F_STR_MAX + 1);

    if (h->http_flavor)
      strncpy((char*)r->http_flavor, (char*)h->http_flavor, P0F_STR_MAX + 1);

  }

  if (h->link_type)
    strncpy((char*)r->link_type, (char*)h->link_type, P0F_STR_MAX + 1);

  if (h->language)
    strncpy((char*)r->language, (char*)h->language, P0F_STR_MAX + 1);

  r->bad_sw      = h->bad_sw;
  r->last_nat    = h->last_nat;
  r->last_chg    = h->last_chg;
  r->up_mod_days = h->up_mod_days;
  r->distance    = h->distance;
  r->os_match_q  = h->last_quality;

  if (h->last_up_min != -1) r->uptime_min = h->last_up_min;

}

void handle_query_host(struct p0f_api_query* q, void **out_data, u32 *out_data_len) {
  struct host_data *h = NULL;
  struct p0f_api_response_header *header;
  struct p0f_api_response_host *body;

  *out_data = ck_alloc(sizeof(struct p0f_api_response_header));
  *out_data_len = sizeof(struct p0f_api_response_header);
  header = *out_data;
  header->magic = P0F_RESP_MAGIC;

  switch (q->addr_type) {
    case P0F_ADDR_IPV4:
    case P0F_ADDR_IPV6:
      h = lookup_host(q->addr, q->addr_type);
      break;
    default:
      WARN("Query with unknown address type %u.\n", q->addr_type);
      header->status = P0F_STATUS_BADQUERY;
      return;
  }

  if (!h) {
    header->status = P0F_STATUS_NOMATCH;
    return;
  }
  header->status = P0F_STATUS_OK;

  *out_data = ck_realloc(*out_data, *out_data_len + sizeof(struct p0f_api_response_host));
  body = *out_data + *out_data_len;
  *out_data_len += sizeof(struct p0f_api_response_host);

  fill_host(body, h);
}

void handle_query_net(struct p0f_api_query* q, void **out_data, u32 *out_data_len) {

  struct p0f_api_response_header *header;
  struct host_data *h = get_newest_host();
  struct host_data **filtered_hosts = NULL;
  u32 count = get_host_count();
  u32 filtered_count = 0;
  u32 *aux;

  *out_data = ck_alloc(sizeof(struct p0f_api_response_header));
  *out_data_len = sizeof(struct p0f_api_response_header);
  header = *out_data;
  header->magic = P0F_RESP_MAGIC;
  header->status = P0F_STATUS_OK;

  if (q->addr_type != P0F_ADDR_IPV4) {
    header->status = P0F_STATUS_NOMATCH;
    return;
  }

  filtered_hosts = ck_alloc(sizeof(struct host_data *) * count);
  while (h) {
    if (h->ip_ver == IP_VER4 && ip_in_network(h->addr, q->addr, q->prefix)) {
      filtered_hosts[filtered_count++] = h;
    }
    h = h->older;
  }

  *out_data = ck_realloc(*out_data, *out_data_len + sizeof(u32));
  aux = *out_data + *out_data_len;
  *out_data_len += sizeof(u32);
  *aux = filtered_count;

  for (count = 0; count < filtered_count; count++) {
    struct p0f_api_response_host *aux2;
    *out_data = ck_realloc(*out_data, *out_data_len + sizeof(struct p0f_api_response_host));
    aux2 = *out_data + *out_data_len;
    *out_data_len += sizeof(struct p0f_api_response_host);
    fill_host(aux2, filtered_hosts[count]);
  }
  ck_free(filtered_hosts);
}

void handle_query(struct p0f_api_query* q, void **out_data, u32 *out_data_len) {

  if (out_data == NULL) {
    WARN("%s: NULL output buffer!", __func__);
    return;
  }

  if (q->magic != P0F_QUERY_MAGIC) {
    struct p0f_api_response_header *r = ck_alloc(sizeof(struct p0f_api_response_header));;
    WARN("Query with bad magic (0x%x).", q->magic);
    r->magic = P0F_RESP_MAGIC;
    r->status = P0F_STATUS_BADQUERY;
    *out_data = (void *) r;
    *out_data_len = sizeof(struct p0f_api_response_header);
    return;
  }

  switch (q->command) {
    case P0F_CMD_QUERY_HOST:
      handle_query_host(q, out_data, out_data_len);
      break;
    case P0F_CMD_QUERY_NET:
      handle_query_net(q, out_data, out_data_len);
      break;
    default:
      WARN("Unknown API command 0x%x\n", q->command);
      return;
  }

}
