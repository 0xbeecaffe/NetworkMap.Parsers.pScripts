#########################################################################
#                                                                       #
#  This file is a Python parser module for Script N'Go Network Map and  #
#  is written to parse VPN tunnel information on Cisco ASA firewalls.   #
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
moduleName = "Cisco ASA VPN Parser"
class CiscoASA_VPN(L3Discovery.IGenericProtocolParser):
  def __init__(self):
    # Describes current operation status
    self.OperationStatusLabel = ""
    # The Router instance associated to this parser. Set in Initialize
    self.Router = None
    #This is the protocol supported by this module
    self.ParsingForProtocols = [ L3Discovery.NeighborProtocol.IPSEC ]
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
    OperationStatusLabel = "Identifying router..."
    #--  
    cToken.ThrowIfCancellationRequested()
    #
    # Compiled regex search patters
    rep_ConnectionIndex = r"^Index\s+:\s(\d+)"
    rep_ConnectionAddress = r"^Connection\s+:\s(.*)"
    rep_Encryption = r"^Encryption\s+:\s(.*)"
    rep_Hashing = r"^Hashing\s+:\s(.*)"
    rep_EncHash = r"^Encryption\s+:\s(.+)Hashing\s+:\s(.+)"
    # rep_IPSecBlocks = r"IPsec:.*\s*(?:(?:(?!^IPsec:)[\s\S])*)"
    rep_LocalAddr = r"Local Addr\s+:\s((?:\d{1,3}.){3}\d{1,3}/(?:\d{1,3}.){3}\d{1,3})"
    rep_RemoteAddr = r"Remote Addr\s+:\s((?:\d{1,3}.){3}\d{1,3}/(?:\d{1,3}.){3}\d{1,3})"
    # get vpn session details for l2l tunnels
    l2lTunnels = Session.ExecCommand("show vpn-sessiondb detail l2l")  
    # extract connection indexes, get match iterator
    connectionIndexes = GetRegexGroupMatches(rep_ConnectionIndex, l2lTunnels, 1)
    try:   
      for thisConnectionIndex in connectionIndexes:
        try:
          # get detail for this connection index
          thisConnectionDetails = Session.ExecCommand("show vpn-sessiondb detail index {0}".format(thisConnectionIndex))
          # extract remote ip address from thisConnectionDetails, get match iterator
          thisConnectionRemoteAddresses = GetRegexGroupMatches(rep_ConnectionAddress, thisConnectionDetails, 1)
          for tunnel_RemoteAddress in thisConnectionRemoteAddresses:
            # get local address for this remote address
            thisConnectionIPSEC = Session.ExecCommand("sh crypto ipsec sa | i remote crypto endpt.: {0}".format(tunnel_RemoteAddress)).splitlines()[0]
            # extract the first ip address from result, that will be the local address
            tunnel_LocalAddress = GetIndexedIPAddressFromLine(thisConnectionIPSEC, 1)
            if tunnel_LocalAddress :
              cipherAlgs = GetRegexGroupMatches(rep_EncHash, thisConnectionDetails, 1)
              if len(cipherAlgs) > 0 : cipherAlg = cipherAlgs[0]
              else : cipherAlg = "n/a"
              hashAlgs = GetRegexGroupMatches(rep_EncHash, thisConnectionDetails, 2)
              if len(hashAlgs) > 0 : hashAlg = hashAlgs[0]
              else : hashAlg = "n/a"
              # get local / remote networks for each ipsec tunnel
              localProxies = GetRegexGroupMatches(rep_LocalAddr, thisConnectionDetails, 1)
              remoteProxies = GetRegexGroupMatches(rep_RemoteAddr, thisConnectionDetails, 1)
              s_localProxies = "\r\n".join(localProxies)
              s_remoteProxies = "\r\n".join(remoteProxies)
              # 
              # RegisterTunnel parameters in order :
              #/// <param name="router">The IRouter requesting registration</param>
              #/// <param name="instance">The routing instance the tunnel is terminating on</param>
              #/// <param name="tunnelProtocol">The protocol used to establish the tunnel</param>
              #/// <param name="tunnelType">The link-type over the tunnel</param>
              #/// <param name="tunnelName">Optional : tunnel name or description</param>
              #/// <param name="tunnelState">Tunnel connection state</param>
              #/// <param name="externalLocalAddress">Tunnel external, local address</param>
              #/// <param name="externalRemoteAddress">Tunnel external, remote address</param>
              #/// <param name="tunnelSourceAddress">Optional : Tunnel internal source address</param>
              #/// <param name="tunnelDestinationAddress">Optional : Tunnel internal destination address</param>
              #/// <param name="localProxy">Optional : the local networks the tunnel is forwarding for. If not empty, must contain valid ipv4 network prefixes per line</param>
              #/// <param name="remoteProxy">Optional : the remote networks the tunnel is forwarding for. If not empty, must contain valid ipv4 network prefixes per line</param>
              #/// <param name="cipher">Optional : the cipher algorithm used by the tunnel</param>
              #/// <param name="hash">Optional : the hashing algorithm used by the tunnel</param>
              #/// <param name="tag">Optional : any data to include. Max length is 1024 characters</param>              
              nRegistry.RegisterTunnel(self.Router, instance, L3Discovery.NeighborProtocol.IPSEC, L3Discovery.LinkType.P2P, None, L3Discovery.NeighborState.Established , tunnel_LocalAddress.strip(), tunnel_RemoteAddress.strip(), None, None, s_localProxies, s_remoteProxies, cipherAlg, hashAlg, None) 
        except Exception as Ex:
          pass
        
    except Exception as Ex:
      message = "CiscoASA Router Module Error : could not parse vpn-sessiondb information because : {1} ".format(str(Ex))
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
  ActionResult = CiscoASA_VPN()
  ScriptSuccess = True