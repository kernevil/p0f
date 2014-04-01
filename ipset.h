#ifndef __IPSET_CREATE_H__
#define __IPSET_CREATE_H__

/* Create a set */
int ipset_create(const char *setname, const char *settype, uint64_t timeout);

/* Destroy a set */
int ipset_destroy(const char *setname);

/* Add an entry to a set */
int ipset_add(const char *setname, const char *addr, uint64_t timeout);

/* Remove an entry from a set */
int ipset_remove(const char *setname, const char *addr);

/* Flush all set entries */
int ipset_flush(const char *setname);

#endif
