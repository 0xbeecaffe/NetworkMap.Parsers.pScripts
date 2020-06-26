#########################################################################
#                                                                       #
#  This file is a Python parser module for Script N'Go Network Map and  #
#  is written to parse static routing on some Hirschmann switches.      #
#                                                                       #
#  You may not use this file without a valid Script N'Go license.       #
#  You may not duplicate or create derivative work from this script     #
#  without a valid Script N'Go license.                                 #
#                                                                       #
#  Copyright Eszközbeszerzés Kft. (c) 2020                              #
#                                                                       #
#########################################################################

import re
import clr
clr.AddReferenceToFileAndPath("SNGInterfaces.dll")
clr.AddReferenceToFileAndPath("NetworkMap.dll")
clr.AddReferenceToFileAndPath("Common.dll")
import L3Discovery
import Scriptngo.Common
from System.Diagnostics import DebugEx, DebugLevel
from System.Net import IPAddress
from Scriptngo.Common import IPOperations
# last changed : 2020.04.14
scriptVersion = "9.0.0"
moduleName = "Hirschmann switch static route parser"
class Hirschmann_STATIC(L3Discovery.IGenericProtocolParser):
  def __init__(self):
    # Describes current operation status
    self.OperationStatusLabel = ""
    # The Router instance associated to this parser. Set in Initialize
    self.Router = None
    #This is the protocol supported by this module
    self.ParsingForProtocols = [ L3Discovery.NeighborProtocol.STATIC ]
    #This is the vendor name supported by this module
    self.ParsingForVendor = "Hirschmann"  
  
  ### ---=== IGenericProtocolParser implementtion ===---- ###
  def GetOperationStatusLabel(self):
    return self.OperationStatusLabel
     
  def Initialize(self, router, protocol):
    """ Initialize this instance. Must return whether router and protocol parameters are supported by this instance"""
    self.Router = router
    if protocol in self.ParsingForProtocols :
      return self.Router.GetVendor() == self.ParsingForVendor
    else:
      return False    
    
  def Parse(self, nRegistry, cToken, instance) :
    """Collects information about active tunnels and registers them with Network Discovery Engine"""
    # The neighbor registry object is received as parameter
    # This must be used to register a new neighbor for further discovery.
    # --
    # A CancellationToken is also passed as parameter. The token should be checked repetitively whether cancellation was requested 
    # by user and if yes, stop further processing.
    # --
    # The RoutingInstance object to work with is also passed as a parameter
    instanceName = "default"
    if instance : instanceName = instance.Name.lower()
    OperationStatusLabel = "Collecting ip routes..."
    cToken.ThrowIfCancellationRequested()
    routes = Session.ExecCommand("show ip route static")
    cToken.ThrowIfCancellationRequested()
    OperationStatusLabel = "Processing STATIC route entries..."
    # regex groups => 1 : network, 2 : subnet mask, 3 : preference, 4 : next-hop, 5: status, 6 : out interface
    rep_StaticWithAddressOnly = r"^(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s+(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s+(\d+)\s+(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s+([^\s]+)\s+([^\s]+)"   
    # Enumerate static routes containing addresses only
    static_with_address = re.finditer(rep_StaticWithAddressOnly, routes, re.MULTILINE)
    for matchnum, match in enumerate(static_with_address):
      try:
        # Group 1 : destination network, Group 2 : metric, Group 3 : dst. network mask, Group 4: next-hop, Group5 : outgoing interface
        networkAddress = match.group(1).strip()
        networkAddressMask = match.group(2).strip()
        maskLength = IPOperations.GetMaskLength(networkAddressMask)
        routeForNetwork = "{0}/{1}".format(networkAddress, maskLength)
        metric = match.group(3).strip()
        nexthop = match.group(4).strip()
        routeStatus = match.group(5).strip()
        outInterfaceName = match.group(6).strip()
        ri = self.Router.GetInterfaceByName(outInterfaceName, instance)
        if ri != None:
          OperationStatusLabel = "Registering static neighbor {0}...".format(ri.Address)
          nRegistry.RegisterSTATICNeighbor( self.Router, instance, routeForNetwork, nexthop, ri.Address, ri); 
      except Exception as Ex:
        message = "Hirschmann Static route parser: could not parse a static route entry because : {0} ".format(str(Ex))
        DebugEx.WriteLine(message) 
    
  def Reset(self):
    """Instructs the router object to reset its internal state and cache if any"""
    pass
    
  def GetSupportTag(self):
    """Must return a string that describes the function of this protocol parser, like supported model, platform, version, protocol, etc..."""
    return "{0} v{1}".format(moduleName, scriptVersion)
  
  def GetVendor(self):
    """Must return a string matching the Vendor name this parser is responible for"""
    return self.ParsingForVendor
    
  def GetSupportedProtocols(self):
    """Returns the list of neighbor protocols supported by this parser"""
    return self.ParsingForProtocols
    
  def ProtocolDependentParser(self, protocol):
    """Can return an specific routing protocol parser responsible for handling that particular protocol's functionality"""
    return None          
        
################### Script entry point ###################
if ConnectionInfo.Command == "CreateInstance":
  ActionResult = Hirschmann_STATIC()
  ScriptSuccess = True