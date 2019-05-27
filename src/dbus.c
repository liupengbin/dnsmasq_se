/* dnsmasq is Copyright (c) 2000-2018 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
     
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dnsmasq.h"

#ifdef HAVE_DBUS

#include <dbus/dbus.h>

const char* introspection_xml_template =
"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
"\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
"<node name=\"" DNSMASQ_PATH "\">\n"
"  <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
"    <method name=\"Introspect\">\n"
"      <arg name=\"data\" direction=\"out\" type=\"s\"/>\n"
"    </method>\n"
"  </interface>\n"
"  <interface name=\"%s\">\n"
"    <method name=\"ClearCache\">\n"
"    </method>\n"
"    <method name=\"GetVersion\">\n"
"      <arg name=\"version\" direction=\"out\" type=\"s\"/>\n"
"    </method>\n"
#ifdef HAVE_LOOP
"    <method name=\"GetLoopServers\">\n"
"      <arg name=\"server\" direction=\"out\" type=\"as\"/>\n"
"    </method>\n"
#endif
"    <method name=\"SetServers\">\n"
"      <arg name=\"servers\" direction=\"in\" type=\"av\"/>\n"
"    </method>\n"
"    <method name=\"SetDomainServers\">\n"
"      <arg name=\"servers\" direction=\"in\" type=\"as\"/>\n"
"    </method>\n"
"    <method name=\"SetServersEx\">\n"
"      <arg name=\"servers\" direction=\"in\" type=\"aas\"/>\n"
"    </method>\n"
"    <method name=\"SetFilterWin2KOption\">\n"
"      <arg name=\"filterwin2k\" direction=\"in\" type=\"b\"/>\n"
"    </method>\n"
"    <method name=\"SetBogusPrivOption\">\n"
"      <arg name=\"boguspriv\" direction=\"in\" type=\"b\"/>\n"
"    </method>\n"
"    <signal name=\"DhcpLeaseAdded\">\n"
"      <arg name=\"ipaddr\" type=\"s\"/>\n"
"      <arg name=\"hwaddr\" type=\"s\"/>\n"
"      <arg name=\"hostname\" type=\"s\"/>\n"
"    </signal>\n"
"    <signal name=\"DhcpLeaseDeleted\">\n"
"      <arg name=\"ipaddr\" type=\"s\"/>\n"
"      <arg name=\"hwaddr\" type=\"s\"/>\n"
"      <arg name=\"hostname\" type=\"s\"/>\n"
"    </signal>\n"
"    <signal name=\"DhcpLeaseUpdated\">\n"
"      <arg name=\"ipaddr\" type=\"s\"/>\n"
"      <arg name=\"hwaddr\" type=\"s\"/>\n"
"      <arg name=\"hostname\" type=\"s\"/>\n"
"    </signal>\n"
"    <method name=\"GetMetrics\">\n"
"      <arg name=\"metrics\" direction=\"out\" type=\"a{su}\"/>\n"
"    </method>\n"
"  </interface>\n"
"</node>\n";

static char *introspection_xml = NULL;

struct watch {
  DBusWatch *watch;      
  struct watch *next;
};


static dbus_bool_t add_watch(DBusWatch *watch, void *data)
{
  struct watch *w;

  for (w = daemon->watches; w; w = w->next)
    if (w->watch == watch)
      return TRUE;

  if (!(w = whine_malloc(sizeof(struct watch))))
    return FALSE;

  w->watch = watch;
  w->next = daemon->watches;
  daemon->watches = w;

  w = data; /* no warning */
  return TRUE;
}

static void remove_watch(DBusWatch *watch, void *data)
{
  struct watch **up, *w, *tmp;  
  
  for (up = &(daemon->watches), w = daemon->watches; w; w = tmp)
    {
      tmp = w->next;
      if (w->watch == watch)
	{
	  *up = tmp;
	  free(w);
	}
      else
	up = &(w->next);
    }

  w = data; /* no warning */
}

static void dbus_read_servers(DBusMessage *message)
{
  DBusMessageIter iter;
  union  mysockaddr addr, source_addr;
  char *domain;
  
  dbus_message_iter_init(message, &iter);

  mark_servers(SERV_FROM_DBUS);
  
  while (1)
    {
      int skip = 0;

      if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_UINT32)
	{
	  u32 a;
	  
	  dbus_message_iter_get_basic(&iter, &a);
	  dbus_message_iter_next (&iter);
	  
#ifdef HAVE_SOCKADDR_SA_LEN
	  source_addr.in.sin_len = addr.in.sin_len = sizeof(struct sockaddr_in);
#endif
	  addr.in.sin_addr.s_addr = ntohl(a);
	  source_addr.in.sin_family = addr.in.sin_family = AF_INET;
	  addr.in.sin_port = htons(NAMESERVER_PORT);
	  source_addr.in.sin_addr.s_addr = INADDR_ANY;
	  source_addr.in.sin_port = htons(daemon->query_port);
	}
      else if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_BYTE)
	{
	  unsigned char p[sizeof(struct in6_addr)];
	  unsigned int i;

	  skip = 1;

	  for(i = 0; i < sizeof(struct in6_addr); i++)
	    {
	      dbus_message_iter_get_basic(&iter, &p[i]);
	      dbus_message_iter_next (&iter);
	      if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BYTE)
		{
		  i++;
		  break;
		}
	    }

#ifndef HAVE_IPV6
	  my_syslog(LOG_WARNING, _("attempt to set an IPv6 server address via DBus - no IPv6 support"));
#else
	  if (i == sizeof(struct in6_addr))
	    {
	      memcpy(&addr.in6.sin6_addr, p, sizeof(struct in6_addr));
#ifdef HAVE_SOCKADDR_SA_LEN
              source_addr.in6.sin6_len = addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
              source_addr.in6.sin6_family = addr.in6.sin6_family = AF_INET6;
              addr.in6.sin6_port = htons(NAMESERVER_PORT);
              source_addr.in6.sin6_flowinfo = addr.in6.sin6_flowinfo = 0;
	      source_addr.in6.sin6_scope_id = addr.in6.sin6_scope_id = 0;
              source_addr.in6.sin6_addr = in6addr_any;
              source_addr.in6.sin6_port = htons(daemon->query_port);
	      skip = 0;
	    }
#endif
	}
      else
	/* At the end */
	break;
      
      /* process each domain */
      do {
	if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING)
	  {
	    dbus_message_iter_get_basic(&iter, &domain);
	    dbus_message_iter_next (&iter);
	  }
	else
	  domain = NULL;
	
	if (!skip)
	  add_update_server(SERV_FROM_DBUS, &addr, &source_addr, NULL, domain);
     
      } while (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING); 
    }
   
  /* unlink and free anything still marked. */
  cleanup_servers();
}

#ifdef HAVE_LOOP
static DBusMessage *dbus_reply_server_loop(DBusMessage *message)
{
  DBusMessageIter args, args_iter;
  struct server *serv;
  DBusMessage *reply = dbus_message_new_method_return(message);
   
  dbus_message_iter_init_append (reply, &args);
  dbus_message_iter_open_container (&args, DBUS_TYPE_ARRAY,DBUS_TYPE_STRING_AS_STRING, &args_iter);

  for (serv = daemon->servers; serv; serv = serv->next)
    if (serv->flags & SERV_LOOP)
      {
	prettyprint_addr(&serv->addr, daemon->addrbuff);
	dbus_message_iter_append_basic (&args_iter, DBUS_TYPE_STRING, &daemon->addrbuff);
      }
  
  dbus_message_iter_close_container (&args, &args_iter);

  return reply;
}
#endif

static DBusMessage* dbus_read_servers_ex(DBusMessage *message, int strings)
{
  DBusMessageIter iter, array_iter, string_iter;
  DBusMessage *error = NULL;
  const char *addr_err;
  char *dup = NULL;
  
  if (!dbus_message_iter_init(message, &iter))
    {
      return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                    "Failed to initialize dbus message iter");
    }

  /* check that the message contains an array of arrays */
  if ((dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) ||
      (dbus_message_iter_get_element_type(&iter) != (strings ? DBUS_TYPE_STRING : DBUS_TYPE_ARRAY)))
    {
      return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                    strings ? "Expected array of string" : "Expected array of string arrays");
     }
 
  mark_servers(SERV_FROM_DBUS);

  /* array_iter points to each "as" element in the outer array */
  dbus_message_iter_recurse(&iter, &array_iter);
  while (dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_INVALID)
    {
      const char *str = NULL;
      union  mysockaddr addr, source_addr;
      int flags = 0;
      char interface[IF_NAMESIZE];
      char *str_addr, *str_domain = NULL;

      if (strings)
	{
	  dbus_message_iter_get_basic(&array_iter, &str);
	  if (!str || !strlen (str))
	    {
	      error = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					     "Empty string");
	      break;
	    }
	  
	  /* dup the string because it gets modified during parsing */
	  if (dup)
	    free(dup);
	  if (!(dup = str_domain = whine_malloc(strlen(str)+1)))
	    break;
	  
	  strcpy(str_domain, str);

	  /* point to address part of old string for error message */
	  if ((str_addr = strrchr(str, '/')))
	    str = str_addr+1;
	  
	  if ((str_addr = strrchr(str_domain, '/')))
	    {
	      if (*str_domain != '/' || str_addr == str_domain)
		{
		  error = dbus_message_new_error_printf(message,
							DBUS_ERROR_INVALID_ARGS,
							"No domain terminator '%s'",
							str);
		  break;
		}
	      *str_addr++ = 0;
	      str_domain++;
	    }
	  else
	    {
	      str_addr = str_domain;
	      str_domain = NULL;
	    }

	  
	}
      else
	{
	  /* check the types of the struct and its elements */
	  if ((dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_ARRAY) ||
	      (dbus_message_iter_get_element_type(&array_iter) != DBUS_TYPE_STRING))
	    {
	      error = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					     "Expected inner array of strings");
	      break;
	    }
	  
	  /* string_iter points to each "s" element in the inner array */
	  dbus_message_iter_recurse(&array_iter, &string_iter);
	  if (dbus_message_iter_get_arg_type(&string_iter) != DBUS_TYPE_STRING)
	    {
	      /* no IP address given */
	      error = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					     "Expected IP address");
	      break;
	    }
	  
	  dbus_message_iter_get_basic(&string_iter, &str);
	  if (!str || !strlen (str))
	    {
	      error = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					     "Empty IP address");
	      break;
	    }
	  
	  /* dup the string because it gets modified during parsing */
	  if (dup)
	    free(dup);
	  if (!(dup = str_addr = whine_malloc(strlen(str)+1)))
	    break;
	  
	  strcpy(str_addr, str);
	}

      memset(&addr, 0, sizeof(addr));
      memset(&source_addr, 0, sizeof(source_addr));
      memset(&interface, 0, sizeof(interface));

      /* parse the IP address */
      if ((addr_err = parse_server(str_addr, &addr, &source_addr, (char *) &interface, &flags)))
	{
          error = dbus_message_new_error_printf(message, DBUS_ERROR_INVALID_ARGS,
                                                "Invalid IP address '%s': %s",
                                                str, addr_err);
          break;
        }
      
      /* 0.0.0.0 for server address == NULL, for Dbus */
      if (addr.in.sin_family == AF_INET &&
          addr.in.sin_addr.s_addr == 0)
        flags |= SERV_NO_ADDR;
      
      if (strings)
	{
	  char *p;
	  
	  do {
	    if (str_domain)
	      {
		if ((p = strchr(str_domain, '/')))
		  *p++ = 0;
	      }
	    else 
	      p = NULL;
	    
	    add_update_server(flags | SERV_FROM_DBUS, &addr, &source_addr, interface, str_domain);
	  } while ((str_domain = p));
	}
      else
	{
	  /* jump past the address to the domain list (if any) */
	  dbus_message_iter_next (&string_iter);
	  
	  /* parse domains and add each server/domain pair to the list */
	  do {
	    str = NULL;
	    if (dbus_message_iter_get_arg_type(&string_iter) == DBUS_TYPE_STRING)
	      dbus_message_iter_get_basic(&string_iter, &str);
	    dbus_message_iter_next (&string_iter);
	    
	    add_update_server(flags | SERV_FROM_DBUS, &addr, &source_addr, interface, str);
	  } while (dbus_message_iter_get_arg_type(&string_iter) == DBUS_TYPE_STRING);
	}
	 
      /* jump to next element in outer array */
      dbus_message_iter_next(&array_iter);
    }

  cleanup_servers();

  if (dup)
    free(dup);

  return error;
}

static DBusMessage *dbus_set_bool(DBusMessage *message, int flag, char *name)
{
  DBusMessageIter iter;
  dbus_bool_t enabled;

  if (!dbus_message_iter_init(message, &iter) || dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BOOLEAN)
    return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS, "Expected boolean argument");
  
  dbus_message_iter_get_basic(&iter, &enabled);

  if (enabled)
    { 
      my_syslog(LOG_INFO, _("Enabling --%s option from D-Bus"), name);
      set_option_bool(flag);
    }
  else
    {
      my_syslog(LOG_INFO, _("Disabling --%s option from D-Bus"), name);
      reset_option_bool(flag);
    }

  return NULL;
}

static DBusMessage *dbus_get_metrics(DBusMessage* message)
{
  DBusMessage *reply = dbus_message_new_method_return(message);
  DBusMessageIter array, dict, iter;
  int i;

  dbus_message_iter_init_append(reply, &iter);
  dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{su}", &array);

  for (i = 0; i < __METRIC_MAX; i++) {
    const char *key     = get_metric_name(i);
    dbus_uint32_t value = daemon->metrics[i];

    dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY, NULL, &dict);
    dbus_message_iter_append_basic(&dict, DBUS_TYPE_STRING, &key);
    dbus_message_iter_append_basic(&dict, DBUS_TYPE_UINT32, &value);
    dbus_message_iter_close_container(&array, &dict);
  }

  dbus_message_iter_close_container(&iter, &array);

  return reply;
}

DBusHandlerResult message_handler(DBusConnection *connection, 
				  DBusMessage *message, 
				  void *user_data)
{
  char *method = (char *)dbus_message_get_member(message);
  DBusMessage *reply = NULL;
  int clear_cache = 0, new_servers = 0;
    
  if (dbus_message_is_method_call(message, DBUS_INTERFACE_INTROSPECTABLE, "Introspect"))
    {
      /* string length: "%s" provides space for termination zero */
      if (!introspection_xml && 
	  (introspection_xml = whine_malloc(strlen(introspection_xml_template) + strlen(daemon->dbus_name))))
	sprintf(introspection_xml, introspection_xml_template, daemon->dbus_name);
    
      if (introspection_xml)
	{
	  reply = dbus_message_new_method_return(message);
	  dbus_message_append_args(reply, DBUS_TYPE_STRING, &introspection_xml, DBUS_TYPE_INVALID);
	}
    }
  else if (strcmp(method, "GetVersion") == 0)
    {
      char *v = VERSION;
      reply = dbus_message_new_method_return(message);
      
      dbus_message_append_args(reply, DBUS_TYPE_STRING, &v, DBUS_TYPE_INVALID);
    }
#ifdef HAVE_LOOP
  else if (strcmp(method, "GetLoopServers") == 0)
    {
      reply = dbus_reply_server_loop(message);
    }
#endif
  else if (strcmp(method, "SetServers") == 0)
    {
      dbus_read_servers(message);
      new_servers = 1;
    }
  else if (strcmp(method, "SetServersEx") == 0)
    {
      reply = dbus_read_servers_ex(message, 0);
      new_servers = 1;
    }
  else if (strcmp(method, "SetDomainServers") == 0)
    {
      reply = dbus_read_servers_ex(message, 1);
      new_servers = 1;
    }
  else if (strcmp(method, "SetFilterWin2KOption") == 0)
    {
      reply = dbus_set_bool(message, OPT_FILTER, "filterwin2k");
    }
  else if (strcmp(method, "SetBogusPrivOption") == 0)
    {
      reply = dbus_set_bool(message, OPT_BOGUSPRIV, "bogus-priv");
    }
  else if (strcmp(method, "GetMetrics") == 0)
    {
      reply = dbus_get_metrics(message);
    }
  else if (strcmp(method, "ClearCache") == 0)
    clear_cache = 1;
  else
    return (DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
   
  if (new_servers)
    {
      my_syslog(LOG_INFO, _("setting upstream servers from DBus"));
      check_servers();
      if (option_bool(OPT_RELOAD))
	clear_cache = 1;
    }

  if (clear_cache)
    clear_cache_and_reload(dnsmasq_time());
  
  method = user_data; /* no warning */

  /* If no reply or no error, return nothing */
  if (!reply)
    reply = dbus_message_new_method_return(message);

  if (reply)
    {
      dbus_connection_send (connection, reply, NULL);
      dbus_message_unref (reply);
    }

  return (DBUS_HANDLER_RESULT_HANDLED);
}
 

/* returns NULL or error message, may fail silently if dbus daemon not yet up. */
char *dbus_init(void)
{
  DBusConnection *connection = NULL;
  DBusObjectPathVTable dnsmasq_vtable = {NULL, &message_handler, NULL, NULL, NULL, NULL };
  DBusError dbus_error;
  DBusMessage *message;

  dbus_error_init (&dbus_error);
  if (!(connection = dbus_bus_get (DBUS_BUS_SYSTEM, &dbus_error)))
    return NULL;
    
  dbus_connection_set_exit_on_disconnect(connection, FALSE);
  dbus_connection_set_watch_functions(connection, add_watch, remove_watch, 
				      NULL, NULL, NULL);
  dbus_error_init (&dbus_error);
  dbus_bus_request_name (connection, daemon->dbus_name, 0, &dbus_error);
  if (dbus_error_is_set (&dbus_error))
    return (char *)dbus_error.message;
  
  if (!dbus_connection_register_object_path(connection,  DNSMASQ_PATH, 
					    &dnsmasq_vtable, NULL))
    return _("could not register a DBus message handler");
  
  daemon->dbus = connection; 
  
  if ((message = dbus_message_new_signal(DNSMASQ_PATH, daemon->dbus_name, "Up")))
    {
      dbus_connection_send(connection, message, NULL);
      dbus_message_unref(message);
    }

  return NULL;
}
 

void set_dbus_listeners(void)
{
  struct watch *w;
  
  for (w = daemon->watches; w; w = w->next)
    if (dbus_watch_get_enabled(w->watch))
      {
	unsigned int flags = dbus_watch_get_flags(w->watch);
	int fd = dbus_watch_get_unix_fd(w->watch);
	
	if (flags & DBUS_WATCH_READABLE)
	  poll_listen(fd, POLLIN);
	
	if (flags & DBUS_WATCH_WRITABLE)
	  poll_listen(fd, POLLOUT);
	
	poll_listen(fd, POLLERR);
      }
}

void check_dbus_listeners()
{
  DBusConnection *connection = (DBusConnection *)daemon->dbus;
  struct watch *w;

  for (w = daemon->watches; w; w = w->next)
    if (dbus_watch_get_enabled(w->watch))
      {
	unsigned int flags = 0;
	int fd = dbus_watch_get_unix_fd(w->watch);
	
	if (poll_check(fd, POLLIN))
	  flags |= DBUS_WATCH_READABLE;
	
	if (poll_check(fd, POLLOUT))
	  flags |= DBUS_WATCH_WRITABLE;
	
	if (poll_check(fd, POLLERR))
	  flags |= DBUS_WATCH_ERROR;

	if (flags != 0)
	  dbus_watch_handle(w->watch, flags);
      }

  if (connection)
    {
      dbus_connection_ref (connection);
      while (dbus_connection_dispatch (connection) == DBUS_DISPATCH_DATA_REMAINS);
      dbus_connection_unref (connection);
    }
}

#endif
