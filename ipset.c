#include <stdarg.h>
#include <libipset/session.h>
#include <libipset/types.h>
#include <libipset/parse.h>
#include "alloc-inl.h"

static struct ipset_session *session = NULL;
static int ipset_session_close();

  static void
ipset_handle_error(const struct ipset_session *session, const char *err, ...)
{
  va_list argptr;
  if (session == NULL) {
    return;
  }
  if (err == NULL) {
    err = (char *)ipset_session_error(session);
  }
  va_start(argptr, err);
  fprintf(stderr, err, argptr);
  va_end(argptr);
  ipset_session_close();
}

  static int
ipset_session_open()
{
  int ret;

  ipset_load_types();
  session = ipset_session_init(printf);
  if (session == NULL) {
    ipset_handle_error(session, "Failed to initialize session");
    return -1;
  }

  /* Do not raise error if creating a set that already exist */
  ret = ipset_envopt_parse(session, IPSET_ENV_EXIST, NULL);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  return 0;
}

  static int
ipset_session_close()
{
  if (session != NULL) {
    ipset_session_fini(session);
  }
  session = NULL;

  return 0;
}

  static int
ipset_set_entry(const char *setname, int cmd, const char *addr)
{
  const struct ipset_type *type;
  int ret;

  ret = ipset_parse_setname(session, IPSET_SETNAME, setname);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  type = ipset_type_get(session, cmd);
  if (type == NULL) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  ret = ipset_parse_elem(session, type->last_elem_optional, addr);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  return 0;
}

  int
ipset_destroy(const char *setname)
{
  int ret;

  ret = ipset_parse_setname(session, IPSET_SETNAME, setname);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  ret = ipset_cmd(session, IPSET_CMD_DESTROY, 0);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  return 0;
}

  int
ipset_flush(const char *setname)
{
  int ret;

  ret = ipset_parse_setname(session, IPSET_SETNAME, setname);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  ret = ipset_cmd(session, IPSET_CMD_FLUSH, 0);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  return 0;
}

  int
ipset_list(const char *setname)
{
  int ret;

  ret = ipset_parse_setname(session, IPSET_SETNAME, setname);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  ret = ipset_cmd(session, IPSET_CMD_LIST, 0);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  return 0;
}

  int
ipset_save(const char *setname)
{
  int ret;

  ret = ipset_parse_setname(session, IPSET_SETNAME, setname);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  ret = ipset_cmd(session, IPSET_CMD_SAVE, 0);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  return 0;
}

  int
ipset_create(const char *setname, const char *settype, uint64_t timeout)
{
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

  ret = ipset_cmd(session, IPSET_CMD_FLUSH, 0);
  if (ret < 0) {
    // Does not exists
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
  }

  ipset_session_close();

  return 0;
}

  int
ipset_add(const char *setname, const char *addr, uint64_t timeout)
{
  int ret;

  DEBUG("[#] Add address '%s' to ipset '%s', timeout '%llu'\n", addr, setname, timeout);
  if (session == NULL) {
    ret = ipset_session_open();
    if (ret < 0) {
      return ret;
    }
  }

  if (timeout != 0) {
    ipset_session_data_set(session, IPSET_OPT_TIMEOUT, &timeout);
  }

  ret = ipset_set_entry(setname, IPSET_CMD_ADD, addr);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  ret = ipset_cmd(session, IPSET_CMD_ADD, 0);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  ipset_session_close();

  return 0;
}

  int
ipset_remove(const char *setname, const char *addr)
{
  int ret;

  DEBUG("[#] Remove address '%s' from ipset '%s'", addr, setname);
  if (session == NULL) {
    ret = ipset_session_open();
    if (ret < 0) {
      return ret;
    }
  }

  ret = ipset_set_entry(setname, IPSET_CMD_DEL, addr);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  ret = ipset_cmd(session, IPSET_CMD_DEL, 0);
  if (ret < 0) {
    ipset_handle_error(session, NULL);
    return -1;
  }

  ipset_session_close();

  return 0;
}


