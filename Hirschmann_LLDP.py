#########################################################################
#                                                                       #
#  This file is a Python parser module for Script N'Go Network Map and  #
#  is written to parse LLDP protocol on certain Hirschmann switches.    #
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
# last changed : 2020.04.14
scriptVersion = "9.0.0"
moduleName = "Hirschmann switch LLDP Parser"
class HirschmannSwitch_LLDP(L3Discovery.IGenericProtocolParser):
  def __init__(self):
    # Describes current operation status
    self.OperationStatusLabel = ""
    # The Router instance associated to this parser. Set in Initialize
    self.Router = None
    #This is the protocol supported by this module
    self.ParsingForProtocols = [ L3Discovery.NeighborProtocol.LLDP ]
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
    """ Perform parsing logic on the given text, which should be relevant to the supported protocols and vendors"""
    # The neighbor registry object is received as parameter
    # This must be used to register a new neighbor for further discovery.
    # --
    # A CancellationToken is also passed as parameter. The token should be checked repetitively whether cancellation was requested 
    # by user and if yes, stop further processing.
    # --
    # The RoutingInstance onject to work with is also passed as a parameter
    instanceName = L3Discovery.RoutingInstance.DefaultInstanceName(self.ParsingForVendor)
    if instance : instanceName = instance.Name
    OperationStatusLabel = "Querying LLDP neighbor data..."
    #--  
    cToken.ThrowIfCancellationRequested()
    #
    # regex search patters
    repRemoteDataBlocks = r"Remote Data.*\s*((?:(?!^Remote Data)[\s\S])*)"
    repConnectingPort = r"^Remote Data,\s(\d+/\d+)"
    repRemoteChassisID = r"Chassis ID [^.]+\.+\s(.*)"
    repRemoteSystemName = r"^\s+System Name\.+\s(.*)"
    repNameOfStation = r"^\s+Name of Station\.+\s(.*)"
    # repLocalPortID : regex group 1 : port number, group2 : module number (optional)GetRegexGroupMatchesGetRegexGroupMatches
    repRemotePortID = r"Port ID [^)]+\)\.+\s(?:port-)?([a-f\d:]+)-?(\d+)?"
    # repRemotePortDescription : regex group 1 : module number, group2 : port number
    repRemotePortDescription = r"Port Description[\.\s]+Module:\s(\d+)\s+Port:\s(\d+)"
    repManagementAddress = r"Management Address\.+\s([a-f\d:.]+)"
    repMACAddress = re.compile(r"[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}", re.IGNORECASE)
    lldpNeighbors = Session.ExecCommand("show lldp neighbors")
    lldpRemoteData = Session.ExecCommand("show lldp remote-data")
    remoteDatablocks = re.finditer(repRemoteDataBlocks, lldpRemoteData, re.MULTILINE | re.IGNORECASE)
    for index, match in enumerate(remoteDatablocks):
      try:
        thisRemoteData = match.group()
        localIntfName = self.GetRegexGroupMatches(repConnectingPort, thisRemoteData, 1)[0].strip()
        ri = self.Router.GetInterfaceByName(localIntfName, instance)
        if ri:
          remoteChassisID = self.GetRegexGroupMatches(repRemoteChassisID, thisRemoteData, 1)
          if remoteChassisID and remoteChassisID[0] : 
            remoteChassisID = remoteChassisID[0].strip()
          else : 
            remoteChassisID = "Unknown Chassis ID"          
          remoteSystemName = self.GetRegexGroupMatches(repRemoteSystemName, thisRemoteData, 1)
          if remoteSystemName and remoteSystemName[0] : 
            remoteSystemName = remoteSystemName[0].strip()
          else : 
            remoteSystemName = self.GetRegexGroupMatches(repNameOfStation, thisRemoteData, 1)
            if remoteSystemName and remoteSystemName[0] : 
              remoteSystemName = remoteSystemName[0].strip()
            else:
              remoteSystemName = "Unknown System Name"
                   
          # First try repRemotePortDescription regex
          remotePortName = self.GetRegexGroupMatches(repRemotePortDescription, thisRemoteData, 2)
          if remotePortName and remotePortName[0]:
            remotePortName = remotePortName[0].strip()
            if remotePortName.isdigit() : remotePortName = str(int(remotePortName))
            remotePortModuleName = self.GetRegexGroupMatches(repRemotePortDescription, thisRemoteData, 1)
            if remotePortModuleName and remotePortModuleName[0]:
              remotePortModuleName = remotePortModuleName[0].strip()          
              if remotePortModuleName.isdigit() : remotePortModuleName = str(int(remotePortModuleName))
              remoteIntfName = "{0}/{1}".format(remotePortModuleName, remotePortName)
            else:
              remoteIntfName  = remotePortName
          else:
            # repRemotePortDescription failed, so let's try repRemotePortID
            remotePortName = self.GetRegexGroupMatches(repRemotePortID, thisRemoteData, 1)
            if remotePortName and remotePortName[0]:
              remotePortName = remotePortName[0].strip()
              if remotePortName.isdigit() : remotePortName = str(int(remotePortName))
              remotePortModuleName = self.GetRegexGroupMatches(repRemotePortID, thisRemoteData, 2)
              if remotePortModuleName and remotePortModuleName[0]:
                remotePortModuleName = remotePortModuleName[0].strip()          
                if remotePortModuleName.isdigit() : remotePortModuleName = str(int(remotePortModuleName))
                remoteIntfName = "{0}/{1}".format(remotePortModuleName, remotePortName)
              else:
                remoteIntfName  = remotePortName            
            
          remoteNeighboringIP = self.GetRegexGroupMatches(repManagementAddress, thisRemoteData, 1)
          if remoteNeighboringIP and remoteNeighboringIP[0] : remoteNeighboringIP = remoteNeighboringIP[0].strip()
          else : remoteNeighboringIP = ""
            
          # Now we have all the data to register the neighbor
          nRegistry.RegisterNeighbor(self.Router, instance, L3Discovery.NeighborProtocol.LLDP,  remoteChassisID, "", remoteSystemName, remoteNeighboringIP, ri, "OK", remoteIntfName) 
        else:
          DebugEx.WriteLine("HirschmannSwitch_LLDP.Parse() : Router object failed to provide details for interface < {0} >".format(localIntfName), DebugLevel.Warning)
      except Exception as Ex:
        DebugEx.WriteLine("Error in HirschmannSwitch_LLDP parser while processing block #{0}. Error is: {1}".format(index, str(Ex)))
        
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
    
  ### ---=== Helper functions ===--- ###  
     
  def GetRegexGroupMatches(self, pattern, text, groupNum):
    """Returns the list of values of specified Regex group number for all matches. Returns Nonde if not matched or groups number does not exist"""
    try:
      result = []
      mi = re.finditer(pattern, text, re.MULTILINE | re.IGNORECASE)
      for matchnum, match in enumerate(mi):
        # regex group 1 contains the connection remote address
        result.append(match.group(groupNum))
      return result
    except :
      return None 
        
################### Script entry point ###################
if ConnectionInfo.Command == "CreateInstance":
  ActionResult = HirschmannSwitch_LLDP()
  ScriptSuccess = True