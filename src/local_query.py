#!/usr/bin/env python

"""
A query interface for the gdp discovery service

### Usage ###

Example:
> guids = find(['temperature', 'photo'], ['permission1', 'permission2'],
               db_user="gdp_discovery", db_passwd="gdp_disc438", 
               db_host="localhost", db_name="discovery_db")
> print guids
> set(['example256bitguid111111111111111', 
  'example256bitguid222222222222222'])

Public interface:
* find:
  Required parameters: list of capabilities and list of permissions
  Optional parameters: discovery server database login information
  (username, password, host and database name)
  Default login information will be used if no login information is
  specified.
  Returns: set of guids which have the specified capabilities and
  at least one of the specified permissions
"""

import MySQLdb

db = None

def with_capability(c):
    """
    Return set of guids wich have capability c
    """
    sql = """SELECT c.client_guid 
             FROM capabilities c
             WHERE c.capability = '%s'""" % c
    cursor = db.cursor()
    cursor.execute(sql)
    results = cursor.fetchall()
    guids = set([])
    for result in results:
        guids.add(result[0])
    db.commit()
    cursor.close()
    return guids

def with_permission(p):
    """
    Return set of guids which have capability p
    """
    sql = """SELECT p.client_guid
             FROM permissions p
             WHERE p.permission = '%s'""" % p
    cursor = db.cursor()
    cursor.execute(sql)
    results = cursor.fetchall()
    guids = set([])
    for result in results:
        guids.add(result[0])
    db.commit()
    cursor.close()
    return guids

def find(capabilities, permissions, db_user="gdp_discovery", 
         db_passwd="gdp_disc438", db_host="localhost", db_name="discovery_db"):
    """
    Return set of guids which have each capability in capabilities and
    at least one permission in permissions
    """
    global db, cursor
    # Create database if it does not exist
    db = MySQLdb.connect(db_host, db_user, db_passwd, db_name)
    have_capabilities = None
    for c in capabilities:
        if not have_capabilities:
            have_capabilities = with_capability(c)
        else:
            have_capabilities &= with_capability(c)
    result = set([])
    if have_capabilities:
        for p in permissions:
            result |= (have_capabilities & with_permission(p))
    db.close()
    return result
    
   
