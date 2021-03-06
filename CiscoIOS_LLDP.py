#########################################################################
#                                                                       #
#  This file is a Python parser module for Script N'Go Network Map and  #
#  is written to parse the configuration on Cisco IOS routers.          #
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
# last changed : 2020.04.15
scriptVersion = "9.0.0"
moduleName = "Cisco IOS LLDP Parser"
class CiscoIOS_LLDP(L3Discovery.IGenericProtocolParser):
  def __init__(self):
    # Describes current operation status
    self.OperationStatusLabel = ""
    # The Router instance associated to this parser. Set in Initialize
    self.Router = None
    #This is the protocol supported by this module
    self.ParsingForProtocols = [ L3Discovery.NeighborProtocol.LLDP ]
    #This is the vendor name supported by this module
    self.ParsingForVendor = "Cisco"  
  
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
    # Split command output to neighbor blocks. WARNING : splitting does not work with line engins \r\n, only if \r removed !
    repNeighborDataBlocks = r"-+\n.*(?:(?:(?!^-+\n)[\s\S])*)"
    repConnectingPort = r"^Local Intf:(.*)"
    repRemoteChassisID = r"^Chassis id:(.*)"
    repRemoteSystemName = r"^System Name:(.*)"
    repNameOfStation = r"^System Description(.*)"   
    repRemotePortID = r"^Port id:(.*)"
    repManagementAddress = r"Management Addresses:\s+ip:(.[\d.]+)"
    
    # Get data from switch
    lldpNeighborData = Session.ExecCommand("show lldp neighbors detail")
    # Must replace \r\n to simply \n
    lldpNeighborData = re.sub(r"\r", "", lldpNeighborData)
    # Parse neighbor data
    neighborDatablocks = re.finditer(repNeighborDataBlocks, lldpNeighborData, re.MULTILINE | re.IGNORECASE)
    for index, match in enumerate(neighborDatablocks):
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
            
          remotePortName = self.GetRegexGroupMatches(repRemotePortID, thisRemoteData, 1)
          remoteIntfName = ""
          if remotePortName and remotePortName[0]:
            remotePortName = remotePortName[0].strip()
            if remotePortName.isdigit() : remotePortName = str(int(remotePortName))
          remoteIntfName  = remotePortName
          remoteNeighboringIP = self.GetRegexGroupMatches(repManagementAddress, thisRemoteData, 1)
          if remoteNeighboringIP and remoteNeighboringIP[0] : remoteNeighboringIP = remoteNeighboringIP[0].strip()
          else : 
            # try resolve from ARP if remote PortName is a MAC address and if that can be resolved from ARP cache
            isremotePortNameMAC = re.findall(r"[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}", remotePortName, re.IGNORECASE) > 0
            if isremotePortNameMAC:
              arpEntry = Session.ExecCommand("show arp | i {0}".format(remotePortName))
              matchedIPs = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", arpEntry, re.IGNORECASE)
              if len(matchedIPs) > 0 : remoteNeighboringIP = matchedIPs[0].strip()
              else : remoteNeighboringIP = ""
            if not remoteNeighboringIP:
              # try if remote chassi ID is MAC and if that can be resolved from ARP cache
              isremoteChassisIsMAC = re.findall(r"[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}", remoteChassisID, re.IGNORECASE) > 0
              if isremoteChassisIsMAC:
                arpEntry = Session.ExecCommand("show arp | i {0}".format(remoteChassisID))
                matchedIPs = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", arpEntry, re.IGNORECASE)
                if len(matchedIPs) > 0 : remoteNeighboringIP = matchedIPs[0].strip() 
              else:
                remoteNeighboringIP = ""             
          # Now we have all the data to register the neighbor
          nRegistry.RegisterNeighbor(self.Router, instance, L3Discovery.NeighborProtocol.LLDP,  remoteChassisID, "", remoteSystemName, remoteNeighboringIP, ri, "OK", remoteIntfName) 
        else:
          DebugEx.WriteLine("CiscoIOS_LLDP.Parse() : Router object failed to provide details for interface < {0} >".format(localIntfName), DebugLevel.Warning)
      except Exception as Ex:
        DebugEx.WriteLine("CiscoIOS_LLDP.Parse() : Error while processing block #{0}. Error is: {1}".format(index, str(Ex)))
        
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
  ActionResult = CiscoIOS_LLDP()
  ScriptSuccess = True