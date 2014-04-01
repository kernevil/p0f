#ifndef __IPSET_CREATE_H__
#define __IPSET_CREATE_H__

int ipset_create(const char *setname, const char *settype, uint64_t timeout);

#endif
