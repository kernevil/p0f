#include <stdarg.h>
#include <libipset/session.h>
#include <libipset/types.h>
#include <libipset/parse.h>
#include "alloc-inl.h"

static struct ipset_session *session = NULL;

static void ipset_handle_error(const struct ipset_session *session,
                              const char *err, ...)
{
  va_list argptr;
  if (err == NULL) {
    err = (char *)ipset_session_error(session);
    if (err == NULL) {
      err = "Unknown error";
    } else {
      //size_t last = strlen(err) - 1;
      //if (err[last] == '\n')
      //  err[last] = '\0';
    }
  }
  va_start(argptr, err);
  fprintf(stderr, err, argptr);
  va_end(argptr);
  //ipset_session_fini(session);
}

int ipset_session_open() {
  int ret;

  ipset_load_types();
  session = ipset_session_init(printf);
  if (session == NULL) {
    ipset_handle_error(session, "Failed to initialize session");
  }

  /* Do not raise error if creating a set that already exist */
  ret = ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  return 0;
}

int ipset_create(const char *setname, const char *settype, uint64_t timeout) {
  int ret;

  DEBUG("[#] Creating ipset: name '%s', type '%s', timeout '%llu'\n", setname, settype, timeout);
  if (session == NULL) {
    ret = ipset_session_open();
    if (ret < 0) {
      return ret;
    }
  }

  ret = ipset_parse_setname(session, IPSET_SETNAME, setname);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  ret = ipset_parse_typename(session, IPSET_OPT_TYPENAME, settype);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  if (timeout != 0) {
    ret = ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout);
    if (ret < 0) {
      ipset_handle_error(session, NULL);
      return -1;
    }
  }

  ret = ipset_cmd(session, IPSET_CMD_CREATE, 0);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  return 0;
}

int ipset_session_close() {
  if (session != NULL) {
    ipset_session_fini(session);
    session = NULL;
  }

  return 0;
}

