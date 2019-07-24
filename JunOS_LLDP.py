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
# last changed : 2019.03.20
scriptVersion = "5.1.0"
moduleName = "JunOS LLDP Parser"
class JunOS_LLDP(L3Discovery.IGenericProtocolParser):
  def __init__(self):
    # Describes current operation status
    self.OperationStatusLabel = ""
    # The Router instance associated to this parser. Set in Initialize
    self.Router = None
    #This is the protocol supported by this module
    self.ParsingForProtocols = [ L3Discovery.NeighborProtocol.LLDP ]
    #This is the vendor name supported by this module
    self.ParsingForVendor = "JunOS"  
  
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
    instanceName = "default"
    if instance : instanceName = instance.Name.lower()
    OperationStatusLabel = "Identifying router..."
    #--  
    cToken.ThrowIfCancellationRequested()
    #
    # Compiled regex search patters
    repChassisType = re.compile(r"(Chassis type\s+:)(.*)", re.IGNORECASE)
    repChassisID = re.compile(r"(Chassis ID\s+:)(.*)", re.IGNORECASE)
    repSystemName = re.compile(r"(System name\s+:)(.*)", re.IGNORECASE)
    repLocalPortID = re.compile(r"(Local Port ID\s+:)(.*)", re.IGNORECASE)
    repPortID = re.compile(r"(Port ID\s+:)(.*)", re.IGNORECASE)
    repPortDescription = re.compile(r"(Port description\s+:)(.*)", re.IGNORECASE)
    repManagementAddress = re.compile(r"(Address\s+:)(.*)", re.IGNORECASE)
    repMACAddress = re.compile(r"[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}", re.IGNORECASE)
    unknownSystemName = "Unknown system"
    unknownChassisType = "Unknown chassis type"
    unknownChassisID = "Unknown chassis id"
    lldpNeighbors = Session.ExecCommand("show lldp neighbors")
    # Output is like below:
    # Local Interface    Parent Interface    Chassis Id          Port info          System Name
    # ge-1/0/6           -                   a4:1f:72:cf:bf:04   a4:1f:72:cf:bf:04
    for thisLine in [line.strip() for line in lldpNeighbors.splitlines()]:
      cToken.ThrowIfCancellationRequested()
      try:
        words = filter(None, thisLine.split(" "))
        if len(words) >= 1 :
          localIntfName = words[0]
          if self.IsInterrestingInterface(localIntfName):  
            # Check if logical unit number is specified in localIntfName
            # localIntfLUN = re.findall(r"\.\d+$", localIntfName)
            ri = self.Router.GetInterfaceByName(localIntfName, instance)
            if ri != None: 
              interfaceLUN = re.findall(r"\.\d+$", localIntfName)
              # Depending on JunOS version, it sometimes reports logical interfaces for LLDP peering that has no configuration
              # In this case wil will take the Physical interface that should have the proper port mode (inherit subinterface) set by JunOS router module
              if ri.PortMode == L3Discovery.RouterInterfacePortMode.Unknown and len(interfaceLUN) == 1:
                phIntfName = re.sub(r"\.\d+$", "", localIntfName)
                ri = self.Router.GetInterfaceByName(phIntfName, instance)
                if ri == None:
                  # Could not find physical interface. This is an error we can't handle, let's continue to next LLDP interface
                  DebugEx.WriteLine("JunOS LLDP Parser error : can't find physical interface {0}".format(phIntfName), DebugLevel.Warning)
                  continue 
                localIntfName = phIntfName       
              # Neighbor registration variables
              remoteChassisID = ""
              remoteIntfName = ""
              remoteSystemName = ""
              remoteNeighboringIP = ""
              # Query LLDP details for this interface
              lldpDetails = Session.ExecCommand("show lldp neighbors interface {0}".format(localIntfName))
              #-- Local Port ID - The SNMP index of the local interface (used to match remote)
              x = repLocalPortID.findall(lldpDetails)
              localPortID = (x[0][1]).strip()  
              ri.SNMPIndex = localPortID
              # Build NeighborInformationBlock          
              niBlock = False
              niBlockText = []
              niText = ""
              for detailLine in lldpDetails.splitlines():         
                if detailLine.lower().startswith("neighbour information") :
                  niBlock = True
                  continue
                elif niBlock:
                  # Empty line makrs the end of block
                  if len(detailLine.strip()) == 0 : break
                  niBlockText.append(detailLine)
              if len(niBlockText) > 0 : niText = "\r\n".join(niBlockText)          
              # Search for interesting information in niText
              #-- SystemName - Optional field in LLDP 
              x = repSystemName.findall(niText)
              if len(x) > 0 : remoteSystemName = (x[0][1]).strip()
              else : remoteSystemName = unknownSystemName
              # -- ChassisID - Mandatory field in LLDP, but VMWare vSwitch does not send this, so be careful
              x = repChassisID.findall(niText)
              if len(x) > 0 : 
                remoteChassisID = (x[0][1]).strip()
              else : remoteChassisID = unknownChassisID
              #-- PortID - Mandatory field in LLDP
              x = repPortID.findall(niText)
              remoteIntfName = (x[0][1]).strip()             
              #-- ChassisType - Optional field in LLDP 
              x = repChassisType.findall(niText)
              if len(x) > 0 : 
                chassisType = (x[0][1]).strip()
                if remoteSystemName == unknownSystemName and chassisType.lower() == "mac address" :
                  # Use remoteChassisID as a unique ID
                  if ri.Description : remoteSystemName = ri.Description
                  else : remoteSystemName = remoteChassisID  
                elif chassisType.lower() == "interface name" :
                  remoteChassisID = remoteSystemName
                elif chassisType.lower() == "network address" :
                  remoteChassisID = remoteSystemName
                  
              else : chassisType = unknownChassisType
              # Find management address if present
              managementBlock = False
              managementBlockText = []
              managementText = ""
              lineIndentLevel = -1
              for detailLine in lldpDetails.splitlines():      
                if detailLine.lower().startswith("management address") :
                  managementBlock = True
                  continue
                elif managementBlock:
                  lineIndentLevel = len(detailLine) - len(detailLine.strip())
                  if lineIndentLevel > 0 :
                    managementBlockText.append(detailLine)
                  pass
                if lineIndentLevel == 0 : break 
                
              if len(managementBlockText) > 0 :
                managementText = "\r\n".join(managementBlockText)
                foundIP = repManagementAddress.findall(managementText)
                if len(foundIP) == 1 :
                  remoteNeighboringIP = (foundIP[0][1]).strip()
              # Now we have all the data to register the neighbor
              nRegistry.RegisterNeighbor(self.Router, instance, L3Discovery.NeighborProtocol.LLDP,  remoteChassisID, "", remoteSystemName, remoteNeighboringIP, ri, "OK", remoteIntfName) 
            else:
              DebugEx.WriteLine("Router object failed to provide details for interface < {0} >".format(localIntfName), DebugLevel.Warning)
      except Exception as Ex:
        DebugEx.WriteLine("Error in JunOS_LLDPParser while parsine line < {0} >. Error is: {1}".format(thisLine, str(Ex)))
        
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
     
  def IsInterrestingInterface(self, intfName):
    """ Determines if a given name is an interface name we want to parse"""
    return intfName.startswith("ge-") or intfName.startswith("xe-") or intfName.startswith("et-") or intfName.startswith("ae") or intfName.startswith("irb") or intfName.startswith("vlan") or intfName.startswith("lo")
    
        
################### Script entry point ###################
if ConnectionInfo.Command == "CreateInstance":
  ActionResult = JunOS_LLDP()
  ScriptSuccess = True