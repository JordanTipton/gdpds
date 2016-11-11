#!/usr/bin/env python

"""
A discovery service for the Global Data Plane (GDP).

This package contains the following modules:
- client_setup: contains a method which prepares a client to use the
  discovery service
- client: should be run in a client application to advertise its
  presence to discovery services
- query: an API for querying the discovery server's database to
  find clients which are accessible in the GDP
- server: a server which advertises a discovery service on a network
  and logs client registrations within a database

### Client Usage ###

For a client to use the discovery service, the following steps must be
taken (optional steps marked with an *):

Done once:
1 - Create an info_log
2*- Create an input and/or output log
3 - Run client_setup.setup_client(<info_log_name>, <signing_key_file>,
    <list of capabilities>, <list of permissions>)
    * optionally, a gdp router, number of clients, CA key and CA cert
      can also be specified
    * a command line implementation can also be used

Done when connecting with discovery service:
4 - Run client.advertise(<guid>, <info_log_name>)
    * optionally, an output_log, input_log, gdp_router, and key_file (which is
      generated during client_setup) can also be specified

### Server usage ###

To run a discovery server, the following steps mmust be taken (optional
steps marked with an *):

1 - Run server.run()
    * optionally, a gdp router, MySQL login information and a list of
      trusted certificates can be specified

### Query usage ###

1 - Call query.find(<list of capabilities>, <list of permissions>)
    * optionally, MySQL login information can be provided

"""

import local_server, client, client_setup, local_query, global_registry, info_log_reader

__all__ = [local_server, client, client_setup, local_query, global_registry, info_log_reader]
