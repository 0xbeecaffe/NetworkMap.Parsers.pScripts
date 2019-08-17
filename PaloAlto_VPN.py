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
# last changed : 2019.07.26
scriptVersion = "0.0.1"
moduleName = "Palo Alto Firewall VPN Parser"
class PaloAlto_VPN(L3Discovery.IGenericProtocolParser):
  def __init__(self):
    # Describes current operation status
    self.OperationStatusLabel = ""
    # The Router instance associated to this parser. Set in Initialize
    self.Router = None
    #This is the protocol supported by this module
    self.ParsingForProtocols = [ L3Discovery.NeighborProtocol.IPSEC ]
    #This is the vendor name supported by this module
    self.ParsingForVendor = "PaloAlto"  
  
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
    # process legacy (not globalprotect) vpn tunnels
    #
    try:   
      # Regex search patters
      rep_vpn_State = r"state:\s+(.*)"
      rep_vpn_localIP = r"^\s+local ip:(\s+[\.\d+]+)"
      rep_vpn_peerIP = r"^\s+peer ip:(\s+[\.\d+]+)"
      rep_Encryption = r"^\s+enc\s+algorithm:(.*)"
      rep_Hashing = r"^\s+auth\s+algorithm:(.*)"
      rep_ProxyBlock = r"(?<=proxy-id:)([\s\S]*)(?=anti replay)"
      rep_localProxies = r"(?:\s+local ip:)(\s+[.\d\/]+)"
      rep_remoteProxies = r"(?:\s+remote ip:)(\s+[.\d\/]+)"
      l2lTunnels = Session.ExecCommand("show vpn tunnel").splitlines()
      # rep_IPSecBlocks = r"IPsec:.*\s*(?:(?:(?!^IPsec:)[\s\S])*)"
      # the line starting with TnID is the header
      columnHeader = next((line for line in l2lTunnels if line.startswith("TnID")), None)
      for vpnLine in l2lTunnels :
        tnID = GetColumnValue(vpnLine, columnHeader, "TnID", "  ")
        if not tnID.isdigit() : 
          continue
        # --
        thisTunnelID = int(tnID)
        tunnel_Name = GetColumnValue(vpnLine, columnHeader, "Name", "  ")
        # get detail for this connection index
        thisTunnelDetails = Session.ExecCommand("show vpn flow tunnel-id {0}".format(thisTunnelID))
        tunnel_StateStr = GetRegexGroupMatches(rep_vpn_State, thisTunnelDetails, 1)[0].strip().lower()
        tunnel_State = L3Discovery.NeighborState.Down;
        if "active" in tunnel_StateStr  : tunnel_State = L3Discovery.NeighborState.Active
        elif "established" in tunnel_StateStr  : tunnel_State = L3Discovery.NeighborState.Established       
        # extract local ip address from thisTunnelDetails
        tunnel_LocalAddress =  GetRegexGroupMatches(rep_vpn_localIP, thisTunnelDetails, 1)[0].strip()
        # extract remote ip address from thisTunnelDetails
        tunnel_PeerAddress =  GetRegexGroupMatches(rep_vpn_peerIP, thisTunnelDetails, 1)[0].strip()
        # get Cipher and Hashing algorithms
        cipherAlg = GetRegexGroupMatches(rep_Encryption, thisTunnelDetails, 1)[0].strip()
        hashAlg = GetRegexGroupMatches(rep_Hashing, thisTunnelDetails, 1)[0].strip()
        # get local / remote networks for each ipsec tunnel
        proxyBlock = GetRegexGroupMatches(rep_ProxyBlock, thisTunnelDetails, 1)[0]
        localProxies = GetRegexGroupMatches(rep_localProxies, proxyBlock, 1)
        s_localProxies = "\r\n".join([s.strip() for s in localProxies])
        remoteProxies = GetRegexGroupMatches(rep_remoteProxies, proxyBlock, 1)
        s_remoteProxies = "\r\n".join([s.strip() for s in remoteProxies])
        # 
        # RegisterTunnel parameters in order :
        #/// <param name="router">The IRouter requesting registration</param>
        #/// <param name="instance">The routing instance the tunnel is terminating on</param>
        #/// <param name="tunnelProtocol">The protocol used to establish the tunnel</param>
        #/// <param name="tunnelType">The link-type over the tunnel</param>
        #/// <param name="tunnelName">Optional : tunnel name or description</param>
        #/// <param name="tunnelState">The connection state</param>
        #/// <param name="externalLocalAddress">Tunnel external, local address</param>
        #/// <param name="externalRemoteAddress">Tunnel external, remote address</param>
        #/// <param name="tunnelSourceAddress">Optional : Tunnel internal source address</param>
        #/// <param name="tunnelDestinationAddress">Optional : Tunnel internal destination address</param>
        #/// <param name="localProxy">Optional : the local networks the tunnel is forwarding for. If not empty, must contain valid ipv4 network prefixes per line</param>
        #/// <param name="remoteProxy">Optional : the remote networks the tunnel is forwarding for. If not empty, must contain valid ipv4 network prefixes per line</param>
        #/// <param name="cipher">Optional : the cipher algorithm used by the tunnel</param>
        #/// <param name="hash">Optional : the hashing algorithm used by the tunnel</param>
        #/// <param name="tag">Optional : any data to include. Max length is 1024 characters</param>              
        nRegistry.RegisterTunnel(self.Router, instance, L3Discovery.NeighborProtocol.IPSEC, L3Discovery.LinkType.P2P, tunnel_Name, tunnel_State,tunnel_LocalAddress, tunnel_PeerAddress, None, None, s_localProxies, s_remoteProxies, cipherAlg, hashAlg, None) 
        
    except Exception as Ex:
      message = "PaloAlto VPN parser : error processing legacy vpn tunnel information. Error is : {0} ".format(str(Ex))
      DebugEx.WriteLine(message)
    #
    # process globalprotect vpn tunnels
    #
    try:   
      gwData = Session.ExecCommand("show global-protect-gateway gateway")
      isLSVPNGateway = "GlobalProtect Gateway" in gwData
      if isLSVPNGateway:
        #
        # Firewall acts as LSVPN Gateway
        #
        rep_gwAddress = r"(?:\s+Local Address\s+\(IPv4\)\s+:)(\s+[.\d\/]+)"
        rep_tunnelEnryption = r"(?:\s+Encryption\s+:)(.*)"
        rep_tunnelAuthentication = r"(?:\s+Authentication\s+:)(.*)"
        rep_tunnelSourceAddress = r"(?:\s+Tunnel Interface IP\s+:)(\s+[.\d\/]+)"
        rep_tunnelDestinationAddress = r"Satellite Tunnel IPs .+:([ .\d]+)"
        # https://stackoverflow.com/questions/52354728/regex-to-split-text-to-blocks
        rep_satelliteBlocks = r"Satellite\s+:.*\s*((?:(?!Satellite\s+:)[\s\S])*)"
        rep_satelliteHostName = r"Satellite Hostname\s+:(.*)"
        rep_satellitePublicIP = r"Public IP .+:([ .\d]+)"
        gateway_Address = GetRegexGroupMatches(rep_gwAddress, gwData, 1)[0].strip()      
        tunnel_SourceAddress = GetRegexGroupMatches(rep_tunnelSourceAddress, gwData, 1)[0].strip()
        tunnel_Encryption = GetRegexGroupMatches(rep_tunnelEnryption, gwData, 1)[0].strip()
        tunnel_Authentication = GetRegexGroupMatches(rep_tunnelAuthentication, gwData, 1)[0].strip()
        # get satellite details
        satelliteData = Session.ExecCommand("show global-protect-gateway current-satellite")
        satelliteBlocks = GetRegexGroupMatches(rep_satelliteBlocks, satelliteData, 1)
        for thisSatelliteBlock in satelliteBlocks:
          tunnel_Name = GetRegexGroupMatches(rep_satelliteHostName, thisSatelliteBlock, 1)[0].strip()
          tunnel_PublicAddress = GetRegexGroupMatches(rep_satellitePublicIP, thisSatelliteBlock, 1)[0].strip()
          tunnel_DestinationAddress = GetRegexGroupMatches(rep_tunnelDestinationAddress, thisSatelliteBlock, 1)[0].strip()        
          # Only satellites with established tunnel status are enlisted by "show global-protect-gateway current-satellite", so no need to query tunnel status here
          nRegistry.RegisterTunnel(self.Router, instance, L3Discovery.NeighborProtocol.IPSEC, L3Discovery.LinkType.P2P, tunnel_Name, L3Discovery.NeighborState.Established, gateway_Address, tunnel_PublicAddress, tunnel_SourceAddress, tunnel_DestinationAddress, None, None, tunnel_Encryption, tunnel_Authentication, None) 
      else:
        #
        # Firewall is not an LSVPN Gateway, check if a Satellite
        #
        gwData = Session.ExecCommand("show global-protect-satellite current-gateway")
        isLSVPNSatellite = "GlobalProtect Satellite" in gwData
        if isLSVPNSatellite :
          #
          # Firewall is an LSVPN Satellite
          #    
          rep_tunnelState = r"Status\s+:(.*)"   
          rep_gwAddress = r"GlobalProtect Gateway Address\s+:(.*)" 
          rep_tunnelDestinationAddress = r"Gateway Tunnel IP\s+:(.*)" 
          rep_tunnelName = r"Gateway Tunnel Name\s+:(.*)" 
          rep_tunnelEnryption = r"(?:\s+Encryption\s+:)(.*)"
          rep_satellitePublicIP = r"(?:\s+Local Address\s+:)(\s+[.\d\/]+)"
          rep_satelliteTunnelInterface = r"\s+Tunnel Interface\s+:\s(.+)"
          gateway_Address = GetRegexGroupMatches(rep_gwAddress, gwData, 1)[0].strip()  
          tunnel_StateStr =  GetRegexGroupMatches(rep_tunnelState, gwData, 1)[0].strip().lower()
          tunnel_State = L3Discovery.NeighborState.Down;
          if "active" in tunnel_StateStr  : tunnel_State = L3Discovery.NeighborState.Active
          elif "established" in tunnel_StateStr  : tunnel_State = L3Discovery.NeighborState.Established
          if tunnel_State == L3Discovery.NeighborState.Active or tunnel_State == L3Discovery.NeighborState.Established :
            tunnel_Encryption = GetRegexGroupMatches(rep_tunnelEnryption, gwData, 1)[0].strip()
          else:
            tunnel_Encryption = "unknown"
          tunnel_DestinationAddress = GetRegexGroupMatches(rep_tunnelDestinationAddress, gwData, 1)[0].strip() 
          tunnel_Name = GetRegexGroupMatches(rep_tunnelName, gwData, 1)[0].strip()       
          # get satellite details
          satelliteData = Session.ExecCommand("show global-protect-satellite satellite")
          tunnel_PublicAddress = GetRegexGroupMatches(rep_satellitePublicIP, satelliteData, 1)[0].strip()
          tunnel_InterfaceName = GetRegexGroupMatches(rep_satelliteTunnelInterface, satelliteData, 1)[0].strip()
          tunnel_SourceAddress = "" 
          ri = self.Router.GetInterfaceByName(tunnel_InterfaceName, instance)
          if ri : 
            tunnel_SourceAddress = ri.Address
          nRegistry.RegisterTunnel(self.Router, instance, L3Discovery.NeighborProtocol.IPSEC, L3Discovery.LinkType.P2P, tunnel_Name, tunnel_State, tunnel_PublicAddress, gateway_Address, tunnel_SourceAddress, tunnel_DestinationAddress, None, None, tunnel_Encryption, "unknown", None) 
           
    except Exception as Ex:
      message = "PaloAlto VPN parser : error processing legacy vpn tunnel information. Error is : {0} ".format(str(Ex))
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
    for matchnum, match in enumerate(mi, start=1):
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
def GetColumnValue(textLine, headerLine, headerColumn, headerSeparator):
  """Returns the substring from textLine in column determined by the position of headerColumn in headerLine"""
  headerColumnNames = map(lambda i: i.strip(), filter(None, headerLine.split(headerSeparator)))
  headerCount = len(headerColumnNames)
  requestedColumnIndex = headerColumnNames.index(headerColumn)
  nextColumnName = ""
  try:
    nextColumnName = headerColumnNames[ requestedColumnIndex + 1 ]
  except:
    pass
  s = headerLine.index(headerColumn)
  e = len(textLine)
  if nextColumnName : e = headerLine.index(nextColumnName)
  return textLine[s:e].strip() 
          
################### Script entry point ###################
if ConnectionInfo.Command == "CreateInstance":
  ActionResult = PaloAlto_VPN()
  ScriptSuccess = True