import sys
# append parent directories to path so can import gdp from gdpds or its parent
sys.path.append("../")
sys.path.append("../../")
import gdp

class InfoLogReader:

    def __init__(self, router_host, router_port):
        if router_host:
            gdp.gdp_init(router_host, router_port)
        else:
            gdp.gdp_init()

    def read(self, name_str):
        """
        Reads a info_log and returns the capabilities, permissions, public key(s)
        (if present) and certificate (if present) described in the info_log

        Parameters:
        name_str - name of the info_log from which to read
        """
        gcl_name = gdp.GDP_NAME(name_str)
        gcl_handle = gdp.GDP_GCL(gcl_name, gdp.GDP_MODE_RO)

        recno = 1
        capabilities = []
        permissions = []
        pkeys = []
        certificate = None
        try:
            datum = gcl_handle.read(recno)
            num_capabilities = int(datum['data'])
            recno += 1
            datum = gcl_handle.read(recno)
            num_permissions = int(datum['data'])
            recno += 1
            datum = gcl_handle.read(recno)
            num_pkeys = int(datum['data'])
            recno += 1
            while recno <= 3 + num_capabilities:
                datum = gcl_handle.read(recno)
                capabilities.append(datum['data'])
                recno += 1
            while recno <= 3 + num_capabilities + num_permissions:
                datum = gcl_handle.read(recno)
                permissions.append(datum['data'])
                recno += 1
            while recno <= 3 + num_capabilities + num_permissions + num_pkeys:
                datum = gcl_handle.read(recno)
                pkeys.append(datum['data'])
                recno += 1  
            datum = gcl_handle.read(recno)
            certificate = datum['data']
        except:
            pass # Error could be because there is no certificate

        return capabilities, permissions, pkeys, certificate

        # capabilities = ["capability1", "capability2", "capability3"]
        # permissions = ["permission1", "permission2", "permission3"]
        # pkeys = ["pkey1", "pkey2", "pkey3", "pkey4"]
        # certificate = "test_certificate"
        # return capabilities, permissions, pkeys, certificate