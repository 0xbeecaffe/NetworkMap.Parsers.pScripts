#########################################################################
#                                                                       #
#  This file is a Python parser module for PGT Network Map and is       #
#  written to parse the configuration on Juniper MX/EX/QFS devices.     #
#                                                                       #
#  You may not use this file without a valid PGT Enterprise license.    #
#  You may not duplicate or create derivative work from this script     #
#  without a valid PGT Enterprise license                               #
#                                                                       #
#  Copyright Laszlo Frank (c) 2014-2019                                 #
#                                                                       #
#########################################################################
import re
import clr
clr.AddReferenceToFileAndPath("PGTInterfaces.dll")
clr.AddReferenceToFileAndPath("PGTNetworkMap.dll")
clr.AddReferenceToFileAndPath("Common.dll")
import L3Discovery
import PGT.Common
from System.Diagnostics import DebugEx, DebugLevel
from System.Net import IPAddress
from PGT.Common import IPOperations
# last changed : 2019.07.29
scriptVersion = "1.0"
moduleName = "Cisco ASA Static route parser"
class CiscoASA_STATIC(L3Discovery.IGenericProtocolParser):
  def __init__(self):
    # Describes current operation status
    self.OperationStatusLabel = ""
    # The Router instance associated to this parser. Set in Initialize
    self.Router = None
    #This is the protocol supported by this module
    self.ParsingForProtocols = [ L3Discovery.NeighborProtocol.STATIC ]
    #This is the vendor name supported by this module
    self.ParsingForVendor = "Cisco-ASA"  
  
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
    routes = Session.ExecCommand("show route")
    cToken.ThrowIfCancellationRequested()
    OperationStatusLabel = "Processing STATIC route entries..."
    rep_StaticWithAddressOnly = r"^S[*\s]+(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})(\s\[[\d\/]+])(?:\s+via\s)(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})(?:,\s+)(.*)"   
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
        outInterfaceName = match.group(5).strip()
        ri = self.Router.GetInterfaceByName(outInterfaceName, instance)
        if ri != None:
          OperationStatusLabel = "Registering static neighbor {0}...".format(ri.Address)
          nRegistry.RegisterSTATICNeighbor( self.Router, instance, routeForNetwork, nexthop, ri.Address, ri); 
      except Exception as Ex:
        message = "CiscoASA Static route parser: could not parse a static route entry because : {0} ".format(str(Ex))
        DebugEx.WriteLine(message) 
    
    # Enumerate static routes containing object names
    rep_StaticWithObjectName = r"^S[*\s]+([\w\-_]+)\s(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})(\s\[[\d\/]+])(?:\s+via\s)(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})(?:,\s+)(.*)"
    static_with_address = re.finditer(rep_StaticWithObjectName, routes, re.MULTILINE)
    for matchnum, match in enumerate(static_with_address):
      try:
        # Group 1 : destination network object name , Group 2 : metric, Group 3 : dst. network mask, Group 4: next-hop, Group5 : outgoing interface
        networkObjectName = match.group(1).strip()
        resolvedObject = self.ResolveObjectSubnet(networkObjectName)
        if resolvedObject:
          networkAddressMask = match.group(2).strip()
          maskLength = IPOperations.GetMaskLength(networkAddressMask)
          routeForNetwork = "{0}/{1}".format(resolvedObject["Subnet"], maskLength)
          metric = match.group(3).strip()
          nexthop = match.group(4).strip()
          outInterfaceName = match.group(5).strip()
          ri = self.Router.GetInterfaceByName(outInterfaceName, instance)
          if ri != None:
            OperationStatusLabel = "Registering static neighbor {0}...".format(ri.Address)
            nRegistry.RegisterSTATICNeighbor( self.Router, instance, routeForNetwork, nexthop, ri.Address, ri)
         
      except Exception as Ex:
        message = "CiscoASA Static route parser: could not parse a static route entry because : {0} ".format(str(Ex))
        DebugEx.WriteLine(message) 
  
  def ResolveObjectSubnet(self, objectName):
    """Returns a dictionary of network address and mask for the given object name like {Subnet:"1.0.0.0", Mask:"255.0.0.0"}"""
    if not objectName:
      return None
    try:
      result = Session.ExecCommand("show run object id {0}".format(objectName))
      rep_SubnetAddressAndMask = r"\s+subnet\s(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)\s(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)"
      subnetAddress = GetRegexGroupMatches(rep_SubnetAddressAndMask, result, 1)[0]
      subnetMask = GetRegexGroupMatches(rep_SubnetAddressAndMask, result, 2)[0]
      return {"Subnet" : subnetAddress, "Mask" : subnetMask}
    except Exception as Ex:
      message = "CiscoASA Static route parser : could not resolve object name : {0}  due to error : {1}".format(objectName, str(Ex))
      DebugEx.WriteLine(message) 
      return None
       
  def Reset(self):
    """Instructs the router object to reset its internal state and cache if any"""
    pass
    
  def GetSupportTag(self):
    """Must return a string that describes the function of this protocol parser, like supported model, platform, version, protocol, etc..."""
    return "{0} v{1}".format(moduleName, scriptVersion)
  
  def GetSupportedProtocols(self):
    """Returns the list of neighbor protocols supported by this parser"""
    return self.ParsingForProtocols
    
  def ProtocolDependentParser(self, protocol):
    """Can return an specific routing protocol parser responsible for handling that particular protocol's functionality"""
    return None
    
### ---=== Helper functions ===--- ###  
 
def GetRegexGroupMatches(pattern, text, groupNum):
  """Returns the list of values of specified Regex group number for all matches. Returns Nonde if not matched or groups number does not exist"""
  try:
    result = []
    mi = re.finditer(pattern, text, re.MULTILINE)
    for matchnum, match in enumerate(mi):
      # regex group 1 contains the connection remote address
      result.append(match.group(groupNum))
    return result
  except :
    return None
          
def GetIndexedIPAddressFromLine(line, index):
  """Extracts the indexed number IP address match from a line of text and returns it. Index is 1 based.
     Expected format is aaa.bbb.ccc.ddd"""
  addresses = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", line)
  if len(addresses) >= index : 
    return addresses[index-1]
  else: 
    return ""             
        
################### Script entry point ###################
if ConnectionInfo.Command == "CreateInstance":
  ActionResult = CiscoASA_STATIC()
  ScriptSuccess = True