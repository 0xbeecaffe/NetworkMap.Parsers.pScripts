#########################################################################
#                                                                       #
#  This file is a Python parser module for PGT Network Map and is       #
#  written to parse the configuration on Cisco ASA devices.             #
#                                                                       #
#  You may not use this file without a valid PGT Enterprise license.    #
#  You may not duplicate or create derivative work from this script     #
#  without a valid PGT Enterprise license                               #
#                                                                       #
#  Copyright Laszlo Frank (c) 2014-2019                                 #
#                                                                       #
#########################################################################
import clr
clr.AddReferenceToFileAndPath("PGTInterfaces.dll")
clr.AddReferenceToFileAndPath("PGTNetworkMap.dll")
clr.AddReferenceToFileAndPath("Common.dll")
import System
import L3Discovery
import PGT.Common
import re
from System.Diagnostics import DebugEx, DebugLevel
from System.Net import IPAddress
from L3Discovery import NeighborProtocol
from PGT.Common import IPOperations
# last changed : 2019.11.17
scriptVersion = "6.0.1"
class CiscoASA(L3Discovery.IRouter):
  # Beyond _maxRouteTableEntries only the default route will be queried
  _maxRouteTableEntries = 10000    
  _defaultRoutingInstanceName = ""
  def __init__(self):
    # The device version info string
    self._versionInfo = None
    # The device inventory string
    self._inventory = None
    # HostName
    self._hostName = None
    # Number of member in a stack
    self._stackCount = 0
    # Not supported by IOS, return default only
    self._logicalSystems = ["Default"]
    # The dictionary of RoutingInstances keyed by LogicalSystem name
    self._routingInstances = {}
    # The routing protocols run by this router, dictionary keyed by routing instamce name
    self._runningRoutingProtocols = {} 
    # The current PGT settings   
    self.ScriptSettings = PGT.Common.SettingsManager.GetCurrentScriptSettings()
    # The ModelNumber calculated from Inventory
    self._ModelNumber = None
    # The SystemSerial calculated from Inventory
    self._SystemSerial = None 
    # Describes the current operation
    self._operationStatusLabel = "Idle"
    # The RouterIDCalculator object
    self._ridCalculator = RouterIDCalculator(self)
    # The InterfaceParser object
    self._interfaceParser = InterfaceParser(self)
    # The vendor definition name this parser supports
    self._supportedVendor = "Cisco-ASA"
    
      
  def GetHostName(self):
    """ Returns the host bane as a string"""
    if not self._hostName : self._hostName = Session.GetHostName()
    return  self._hostName
    
  def GetInventory(self):
    """Returns the device inventory string"""
    if not self._inventory : 
      self._inventory = Session.ExecCommand("show inventory")
    return self._inventory
    
  def GetLogicalSystemNames(self):
    """ Returns the list of Logical Systems as a string list"""
    return self._logicalSystems
    
  def GetManagementIP(self):
    """Returns the management ip address as a string"""
    return ConnectionInfo.DeviceIP
    
  def GetModelNumber(self):
    """Returns Model number as a string, calculated from Inventory"""
    if not self._ModelNumber :
      mn  = ""
      inv = self.GetInventory()
      models = re.findall(r"(?<=DESCR:).*", inv)
      if len(models) >= 1:
        self._ModelNumber = models[0].strip('"')
      else:
        self._ModelNumber = "n/a"
    return self._ModelNumber
    
  def GetOperationStatusLabel(self):
    """Returns a string describibg current activity"""
    return self._operationStatusLabel
    
  def GetPlatform(self):
    """Return a string	to describe device Platform"""
    return "ASA"
    
  def GetSession(self):
    """Returns the actual Session object"""
    return Session
    
  def GetStackCount(self):
    """Returns the number of members in a switch stack"""
    return 1
    
  def GetSupportTag(self):
    """Returns a string describing capability of this instance"""
    global scriptVersion
    return "Cisco Adaptive Security Appliance support module - Python Parser v{0}".format(scriptVersion)
    
  def GetSupportedEngineVersion(self):
    """Returns the regex pattern covering supported Discovery Engine versions"""
    global scriptVersion
    return r"^7\.5.*"    
    
  def GetSystemSerial(self):
    """Returns System serial numbers as a string, calculated from Inventory"""
    if not self._SystemSerial :
      # check inventory for serial numbers
      inv = self.GetInventory()
      SNs = re.findall(r"(?<=SN: ).*", inv, re.IGNORECASE)
      if len(SNs) > 0 :
        self._SystemSerial = SNs[0]
    return self._SystemSerial
    
  def GetSystemMAC(self, instance):
    """Returns the CSV list of MAC addresses associated with the local system for the given routing instance"""
    # For ASA, we skip the instance. Cotexts are not yet supported by this parser
    systemMACs = []
    v = self.GetVersion()
    rep_systemMACs = r"(?!0000)[a-f,0-9]{4}\.[a-f,0-9]{4}\.[a-f,0-9]{4}"
    try:
      ri_systemMACs = re.finditer(rep_systemMACs, v, re.MULTILINE | re.IGNORECASE)
      for index, match in enumerate(ri_systemMACs):
        systemMACs.append(match.group())
      
    except Exception as Ex:
      DebugEx.WriteLine("CiscoASA.GetSystemMAC() : unexpected error : {0}".format(str(Ex)))
    return ",".join(systemMACs)
    
  def GetDeviceType(self):
    """Returns Type string that can be Switch, Router or Firewall, depending on Model"""
    return "Firewall"
    
  def GetVendor(self):
    """Must return a string matching the Vendor name this parser is responible for"""
    return self._supportedVendor
    
  def GetVersion(self):
    """Must return device version string 	"""
    if not self._versionInfo:
      self._versionInfo = Session.ExecCommand("show version")
    return self._versionInfo
  
  def ActiveProtocols(self, instance):
    """Returns the list of NeighborProtocols running on the requested routing instance """
    defaultInstanceName = L3Discovery.RoutingInstance.DefaultInstanceName(self.GetVendor())
    instanceName = defaultInstanceName
    if instance : instanceName = instance.Name
    if self._runningRoutingProtocols.get(instanceName, None) == None:
      self._runningRoutingProtocols[instanceName] = []
    if len(self._runningRoutingProtocols[instanceName]) == 0 :
      # // -- check running routing protocols
      cmd = "show ip protocols"
      if instanceName != defaultInstanceName : 
        cmd = "show ip protocols vrf {0}".format(instanceName)
      response = str.lower(Session.ExecCommand(cmd));
     
      mathcedProtocolNames = []
      matches = re.finditer(r"(?<=routing protocol is ).([a-z]{0,99})", response, re.MULTILINE | re.IGNORECASE)
      for matchNum, match in enumerate(matches, start=1):
        for groupNum in range(0, len(match.groups())):
          groupNum = groupNum + 1     
          mathcedProtocolNames.append(match.group(groupNum)) 
      supportedProtocols = System.Enum.GetValues(clr.GetClrType(L3Discovery.NeighborProtocol))
      for thisProtocol in supportedProtocols :
        if str(thisProtocol).lower() in mathcedProtocolNames : 
          # In case we are checking the global routing instance. we must perform further checks
          # because "show ip protocols" reports all protocols across all VRFs unfortunately
          if instanceName == defaultInstanceName : 
            if thisProtocol == L3Discovery.NeighborProtocol.BGP:
              b = Session.ExecCommand("show ip bgp summary")
              if b : self._runningRoutingProtocols[ instanceName ].Add(thisProtocol)
            elif thisProtocol == L3Discovery.NeighborProtocol.OSPF:
              o = Session.ExecCommand("show ip ospf neighbor")
              if o : self._runningRoutingProtocols[ instanceName ].Add(thisProtocol)
            elif thisProtocol == L3Discovery.NeighborProtocol.EIGRP:
              e = Session.ExecCommand("show ip eigrp neighbor")
              if e : self._runningRoutingProtocols[ instanceName ].Add(thisProtocol)
            elif thisProtocol == L3Discovery.NeighborProtocol.RIP:
              e = Session.ExecCommand("show ip rip neighbor")
              if e : self._runningRoutingProtocols[ instanceName ].Add(thisProtocol)
          else:
            self._runningRoutingProtocols[ instanceName ].Add(thisProtocol)
    
      # STATIC 
      cmd = "show route static"
      response = Session.ExecCommand(cmd);  
      if response : 
        self._runningRoutingProtocols[instance.Name].append(NeighborProtocol.STATIC)  
        
 
      #
      # CDP/LLDP - Apparently, Cisco does not want to implement CDP / LLDP on ASA
      #
      # VPN - supporting L2L IPSec
      if instanceName == defaultInstanceName:
        ipsecTunnels = Session.ExecCommand("show vpn-sessiondb summary | i IPsec")
        numbers = GetRegexGroupMatches(r"\s?ikev\d\sipsec\s+:\s+(\d)", ipsecTunnels, 1)
        if any(n > 0 for n in numbers):
          self._runningRoutingProtocols[instanceName].Add(NeighborProtocol.IPSEC)
          pass    
          
    result =  self._runningRoutingProtocols[instanceName]
    return result
    
  def BGPAutonomousSystem(self, instance):
    """Returns the BGP AN number for the requested routing instance"""
    return self._ridCalculator.GetBGPASNumber(instance)
    
  def GetInterfaceByName(self, interfaceName, instance):
    """Returns the RouterInterface object for the requested interface name"""
    return self._interfaceParser.GetInterfaceByName(interfaceName, instance)
    
  def GetInterfaceConfiguration(self, routerInterface):
    """Return a boolean value if sucessfully updated the Configuration of the routerInterface object specified"""
    try:  
      routerInterface.Configuration = self._interfaceParser.GetInterfaceConfiguration(routerInterface.Name)
      return True
    except:
      return False
    
  def GetInterfaceNameByIPAddress(self, address, instance):
    """Returns the name of the interface specified by ip address"""
    return self._interfaceParser.GetInterfaceNameByAddress(address, instance)
  
  def Initialize(self, session):
    """Return a boolean value indicating whether the current instance is capable of handling the device connected in session"""
    # Session global variable will always contain the actual session, therefore we don't need to
    # keep a referecnce to the session vsariable passed over here
    self._defaultRoutingInstanceName = L3Discovery.RoutingInstance.DefaultInstanceName(self.GetVendor())
    v = self.GetVersion()
    return "adaptive security appliance" in v.lower()
    
  def RegisterNHRP(self, neighborRegistry, instance):
    """Collects NHRP protocol information and registers it with Network Discovery Engine"""
    # ASA does not support HSRP or VRRP
    pass
  
  def Reset(self):
    """Resets all instance variables to its default value"""
    self._versionInfo = None
    self._inventory = None
    self._hostName = None
    self._stackCount = 0
    self._logicalSystems = []
    self._routingInstances = {}
    self._runningRoutingProtocols = {} 
    self.ScriptSettings = PGT.Common.SettingsManager.GetCurrentScriptSettings()
    self._ModelNumber = None
    self._SystemSerial = None 
    self._operationStatusLabel = "Idle"
    self._ridCalculator.Reset()
    self._interfaceParser.Reset()  
    
  def RoutedInterfaces(self, instance):
    """Returns the RouterInterface object list for the requested routing instance"""
    return self._interfaceParser.GetAllInterfaces(instance)
    
  def RouterID(self, protocol, instance):
    """Returns the router ID string for the requested protocol and routing intance"""
    return self._ridCalculator.GetRouterID(protocol, instance)
    
  def RoutingInstances(self, logicalSystemName):
    """Returns the list of RoutingInstance objects for the VRFs running on the requested logical system (VDC)"""
    if not logicalSystemName : 
      logicalSystemName = "Default"
    if self._routingInstances.get(logicalSystemName, None) == None : 
      self._routingInstances[logicalSystemName] = []
      
    if len(self._routingInstances[logicalSystemName]) == 0:
      instances = []
      # ASA does not natively support VRFs, so add the default (global) instance only
      defInstance = L3Discovery.RoutingInstance()
      defInstance.LogicalSystemName = logicalSystemName
      defInstance.DeviceVendor = self._supportedVendor
      defInstance.Name = self._defaultRoutingInstanceName
      instances.append(defInstance)
      self._routingInstances[logicalSystemName] = instances
    
    result = self._routingInstances[logicalSystemName]
    return result
    
  def RouteTableSize(self, instance):
    """Returns the size of the route table for the requested routing instance"""
    instanceName = self._defaultRoutingInstanceName
    if instance : instanceName = instance.Name
    routeTableSize = -1
    try :
      cmd = "show route summary"
            
      routeSummary = Session.ExecCommand(cmd)   
      routeTotals = filter(lambda s: s.startswith("Total"), routeSummary.splitlines())
      
      if len(routeTotals) > 0:
        # return the last number in Total line
        words = filter(None, routeTotals[0].split(' '))
        routeTableSize = int(words[2])
    except Exception as Ex :
      DebugEx.WriteLine("CiscoASA : error calculating route table size : {0}".format(str(Ex)))
    
    return routeTableSize
      
  def RoutingTable(self, instance):
    """Returns the list of RouteTableEntry objects for requested RoutingInstance"""
    parsedRoutes = []
    try:
      if instance : 
        instanceName = instance.Name
      # get route table size
      routeTableSize = self.RouteTableSize(instance)
      if routeTableSize > self._maxRouteTableEntries :
        # query only default route 
        cmd = "show route 0.0.0.0"
      else:
        # query inet.0 route table for the requested instance
        cmd = "show route"
      routes = Session.ExecCommand(cmd)
      
      thisProtocol = NeighborProtocol.UNKNOWN
      expectingNextHop = False
      prefix = ""
      maskLength = -1
      subnettedPrefix = ""
      subnettedMaskLength = -1
      nextHop = ""
      adminDistance = ""
      routeMetric = ""
      parserSuccess = False
      outInterface = ""
      for rLine in [line.strip() for line in routes.splitlines()]:
        if "subnetted" in rLine:
          # lets check if we find an ipAddress subnetMask combination in the line
          m = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b\/\d{1,2}", rLine)
          if len(m) == 1 :
            prefixAndMask = m[0].split('/')
            if len(prefixAndMask) == 2 :
              subnettedPrefix = prefixAndMask[0]
          # proceed to next rLine
          continue
        if rLine.startswith("B") :
          thisProtocol = NeighborProtocol.BGP
          expectingNextHop = False
        elif rLine.startswith("O") or rLine.startswith("IA") or rLine.startswith("N1") or rLine.startswith("N2") or rLine.startswith("E1") or rLine.startswith("E2") :
          thisProtocol = NeighborProtocol.OSPF
          expectingNextHop = False
        elif rLine.startswith("D") or rLine.startswith("EX") :
          thisProtocol = NeighborProtocol.EIGRP;
          expectingNextHop = False;
        elif rLine.startswith("R") :
          thisProtocol = NeighborProtocol.RIP
          expectingNextHop = False
        elif rLine.startswith("L") :
          thisProtocol = NeighborProtocol.LOCAL
          expectingNextHop = False
        elif rLine.startswith("C") :
          thisProtocol = NeighborProtocol.CONNECTED
          expectingNextHop = False
        elif rLine.startswith("S") :
          thisProtocol = NeighborProtocol.STATIC
          expectingNextHop = False
        elif rLine.startswith("[") and expectingNextHop : pass
        else :
          thisProtocol = NeighborProtocol.UNKNOWN
          expectingNextHop = False
        # reset variables if current line is not a continuation
        if not expectingNextHop :
          prefix = ""
          maskLength = -1
          nextHop = ""
          adminDistance = ""
          routeMetric = ""
          parserSuccess = False
          outInterface = ""
        
        if thisProtocol != NeighborProtocol.UNKNOWN :
          if thisProtocol == NeighborProtocol.LOCAL or thisProtocol == NeighborProtocol.CONNECTED :
            # we expect an ip addresses-subnet mask pair in these lines
            prefixAndMask = GetIPAddressAndSubnetMaskFromLine(rLine)
            if prefixAndMask:
              prefix = prefixAndMask[0]
              maskLength = IPOperations.GetMaskLength(prefixAndMask[1])
              # this line should also contain the out interface as the last word
              words = filter(None, rLine.split(','))
              asaNameif = words[-1]
              oif = self._interfaceParser.GetInterfaceByASANameIf(asaNameif, instance)
              if oif : outInterface = oif.Name
              else : outInterface = asaNameif
              expectingNextHop = False
              parserSuccess = True
          else:
            if not expectingNextHop:
              #  we expect an ip addresses-subnet mask pair in these lines, and also a next-hop 
              prefixAndMask = GetIPAddressAndSubnetMaskFromLine(rLine)
              if prefixAndMask:
                prefix = prefixAndMask[0]
                maskLength = IPOperations.GetMaskLength(prefixAndMask[1])
                expectingNextHop = True                    
                
            if expectingNextHop:
              # get next-hop
              m = re.findall(R"(?<=via )\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", rLine)
              if len(m) == 1 :
                expectingNextHop = False
                parserSuccess = True
                nextHop = m[0]
                # get preference
                m = re.findall(r"\[(.*?)\]", rLine)
                if len(m) == 1 :
                  preferences = filter(None, m[0].split('/'))
                  adminDistance = preferences[0].strip('[')
                  routeMetric = preferences[1].strip(']')
                # this line should also contain the out interface
                words = rLine.split(',')
                if len(words) > 1 :                
                  asaNameif = words[-1]
                  oif = self._interfaceParser.GetInterfaceByASANameIf(asaNameif, instance)
                  if oif : outInterface = oif.Name
                  else : outInterface = asaNameif
              else:
                # only for debugging
                expectingNextHop = True               
              
        if parserSuccess:
          try:
            rte = L3Discovery.RouteTableEntry()
            rte.RouterID = self.RouterID(thisProtocol, instance)
            rte.Prefix = prefix
            rte.MaskLength = maskLength
            rte.Protocol = str(thisProtocol)
            rte.AD = adminDistance
            rte.Metric = routeMetric
            rte.NextHop = nextHop
            rte.OutInterface = outInterface
            rte.Best = True # the show ip route output only lists best routes :-(
            rte.Tag = ""
            parsedRoutes.Add(rte)
          except Exception as Ex :
            msg = "CiscoASA.RoutingTable() : error processing route table : {0}".format(str(Ex))
            DebugEx.WriteLine(msg)
              
    except Exception as Ex:
      msg = "CiscoASA.RoutingTable() :unexpected error while processing route table : {0}".format(str(Ex))
      DebugEx.WriteLine(msg)
      raise Exception(msg)
    
    return parsedRoutes
      
class RouterIDCalculator():
  """Performs Router ID and AS Number calculations """
  def __init__(self, router):
    # self.Router will hold a reference to the parent CiscoASA instance
    self.Router = router
    # RouterID is a dictionary in dictionary, outer keyed by RoutingInstance name, inner keyed by RoutingProtocol as a string
    self.RouterID = {}
    # BGPASNumber is a dictionary, keyed by RoutingInstance name
    self.BGPASNumber = {}  
    
  def GetRouterID(self, protocol, instance):
    """Return the RouterID for given instance and protocol"""
    rid = ""
    instanceName = self.Router._defaultRoutingInstanceName
    if instance : instanceName = instance.Name
    if len(self.RouterID.get(instanceName, {})) == 0 : self.CalculateRouterIDAndASNumber(instance)
    instanceRIDs = self.RouterID.get(instanceName, None)
    if instanceRIDs :
      rid = instanceRIDs.get(str(protocol), "")
    return rid
    
  def GetBGPASNumber(self, instance):
    instanceName = self.Router._defaultRoutingInstanceName
    if instance : instanceName = instance.Name
    if len(self.BGPASNumber) == 0 : 
      self.CalculateRouterIDAndASNumber(instance)
    return self.BGPASNumber.get(instanceName, "")
          
  def CalculateRouterIDAndASNumber(self, instance):
    """Parse the RouterID and AS number for the requested RoutingInstance"""  
    instanceName = self.Router._defaultRoutingInstanceName
    if instance : instanceName = instance.Name
    if self.RouterID.get(instanceName, None) == None: self.RouterID[instanceName] = {}
    
    # Determine default router ID
    globalRouterID = ConnectionInfo.DeviceIP
    l3interfaces = Session.ExecCommand("sh interface ip brief")
    if l3interfaces:
      try :
        loopbacks = [intf.lower() for intf in l3interfaces.splitlines() if intf.lower().startswith("loopback") and GetIPAddressFromLine(intf)]
        if len(loopbacks) > 0 :
          # find the loopback with lowest number
          lowestLoopback = sorted(loopbacks, key=lambda i: int(i[8:10]))[0]
          if lowestLoopback:
            globalRouterID = lowestLoopback.split()[1]
        else:
          # no loopbacks, find the interface with highest ip address
          highestIPLine = (sorted(l3interfaces.splitlines(), key=lambda i: IP2Int(GetIPAddressFromLine(i)))[-1]).strip()
          if highestIPLine:
            globalRouterID = GetIPAddressFromLine(highestIPLine)
      except Exception as Ex :
        DebugEx.WriteLine("CiscoASA.CalculateRouterIDAndASNumber() : error while parsing interface information : " + str(Ex))
    
   
    # get the running routing protocols for this routing instance
    runnintRoutingProtocols = self.Router.ActiveProtocols(instance)
    for thisProtocol in runnintRoutingProtocols:  
      if thisProtocol == L3Discovery.NeighborProtocol.BGP:
        # construct CLI command
        cmd = "show bgp summary"
        
        bgpSummary = Session.ExecCommand(cmd)
        match = re.findall(r"(?<=BGP router identifier )[\d.]{0,99}", bgpSummary, re.IGNORECASE)
        if len(match) == 1 :
          self.RouterID[instanceName][str(thisProtocol)] = match[0]
          if globalRouterID == ConnectionInfo.DeviceIP : globalRouterID = match[0]
        
        # get also the BGP AS number
        match = re.findall(r"(?<=local AS number )[\d.]{0,99}", bgpSummary, re.IGNORECASE) 
        if len(match) == 1 :
          self.BGPASNumber[instanceName] = match[0]
        
      elif thisProtocol == L3Discovery.NeighborProtocol.OSPF:
        cmd = "show ospf | i ID"
        ospfGeneral = Session.ExecCommand(cmd)
        # expecting output like this:
			  # Routing Process "ospf 200" with ID 10.9.254.251
				# Routing Process "ospf 100" with ID 192.168.1.1
        #
        # WARNING if more than one EIGRP process is running, generate error
        #        
        if len(ospfGeneral.splitlines()) == 1 :
          match = re.findall(r"(?<=ID )[\d.]{0,99}", ospfGeneral, re.IGNORECASE)
          if len(match) == 1 :
            self.RouterID[instanceName][str(thisProtocol)] = match[0]
            if globalRouterID == ConnectionInfo.DeviceIP : globalRouterID = match[0]
        else:
          raise ValueError("Parsing more than one OSPF process is not supported by parser")
     
      elif thisProtocol == L3Discovery.NeighborProtocol.EIGRP :
        cmd = "show eigrp topology | i ID"
        eigrpGeneral = Session.ExecCommand(cmd)
        # expecting output like this:
        # IP - EIGRP Topology Table for AS(10) / ID(10.9.240.1)
        # IP - EIGRP Topology Table for AS(20) / ID(10.9.240.1)
        #
        # TODO :
        # WARNING if more than one EIGRP process is running, generate error
        #        
        if len(eigrpGeneral.splitlines()) == 1 :
          match = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", eigrpGeneral, re.IGNORECASE)
          if len(match) == 1 :
            self.RouterID[instanceName][str(thisProtocol)] = match[0]
            if globalRouterID == ConnectionInfo.DeviceIP : globalRouterID = match[0]
        else:
          raise ValueError("Parsing more than one EIGRP process is not supportedby parser")        
                
      elif thisProtocol == L3Discovery.NeighborProtocol.CDP:
        # only for default (global) routing instance
        if instanceName == self.Router._defaultRoutingInstanceName :
          self.RouterID[instanceName][str(thisProtocol)] = self.Router.GetHostName()
          
      elif thisProtocol == L3Discovery.NeighborProtocol.RIP:
        # always use global router-id
        # TODO : this may require tuning
        self.RouterID[instanceName][str(thisProtocol)] = globalRouterID       
        
      elif thisProtocol == L3Discovery.NeighborProtocol.STATIC:  
        # always use global router-id
        self.RouterID[instanceName][str(thisProtocol)] = globalRouterID 
      elif thisProtocol == L3Discovery.NeighborProtocol.IPSEC:  
        # Always use global router-id for IPSEC. 
        # From networking perspective this is not meaningful but is rather a requirement of NetworkDiscoveryEngine
        # to associate a routerID for each neighbor protocol that is being discoverd.
        self.RouterID[instanceName][str(thisProtocol)] = globalRouterID         
      else :
        self.RouterID[instanceName][str(thisProtocol)] = globalRouterID   
          
  def Reset(self):
    self.RouterID = {}
    self.BGPASNumber = {}
    
class InterfaceParser(): 
  """Manage Cisco interfaces"""
  def __init__(self, router):
    #  self.Router will hold a reference to the parent CiscoASA instance
    self.Router = router
    # These are the list of interfaces collected by ParseInterfaces() method. 
    # A dictionary, keyed by routing instance name and containing Lists
    self.Interfaces = {}
    # Interface config cache. 
    # A dictionary keyed by Interface Name and containing strings
    self._interfaceConfigurations = {}
    # The running configuration of router
    self._running_config = None
    # A dictionary to map interface names to ASA nameif properties
    self._ifNames = {}
    # A dictionary to map ASA nameif properties to interface names
    self._nameIfs = {}
    
  def ParseInterfaces(self, instance) :
    """Collects interface details for all interfaces of specified routing instance, but do not collect interface configuration """
    # Get the interfaces configurations
    if len(self._interfaceConfigurations) == 0 : self.ParseInterfaceConfigurations()
    # Init interface dictionary for instance
    instanceName = self.Router._defaultRoutingInstanceName
    if instance : instanceName = instance.Name
    if self.Interfaces.get(instanceName, None) == None:
      self.Interfaces[instanceName] = [] 
    # Query the device interfaces
    interfaces = Session.ExecCommand("show interface summary").splitlines()
    # Add a dummy line at the end, required for below processing only
    interfaces.append("--end--")
    # Parse the result and fill up self.Interfaces list
    ri = L3Discovery.RouterInterface()
    lineCount = len(interfaces)
    currentLineIndex = 1
    rep_MAC = r"(?!0000)[a-f,0-9]{4}\.[a-f,0-9]{4}\.[a-f,0-9]{4}"
    for line in interfaces:
      try:  
        if line.lower().startswith("interface") or currentLineIndex == lineCount :
          # this is either a new interface block, or the end of the interface list
          if ri and ri.Name :
            # Add actual interface if vrf name matches instanceName
            if not ri.VRFName and instanceName == self.Router._defaultRoutingInstanceName or ri.VRFName == instanceName:
              ri.Configuration = self.GetInterfaceConfiguration(ri.Name)
              if ri.Configuration.find("vlan ") >= 0 : 
                ri.PortMode = L3Discovery.RouterInterfacePortMode.L3Subinterface
                subinterfaceDefinition = next((cline for cline in ri.Configuration.splitlines() if cline.startswith("vlan ")), "")
                ri.VLANS = subinterfaceDefinition.split(' ')[-1]
              elif ri.Address : ri.PortMode = L3Discovery.RouterInterfacePortMode.Routed
              else : ri.PortMode = L3Discovery.RouterInterfacePortMode.Unknown
              ri.Description = next((cline for cline in ri.Configuration.splitlines() if cline.startswith("description")), "")
              self.Interfaces[instanceName].Add(ri)  
            if currentLineIndex == lineCount :
              break
          words = filter(None, line.split(' '))
          interfaceName = words[1]
          if self.IsInterrestingInterface(interfaceName):
            # Create new interface    
            ri = L3Discovery.RouterInterface()
            # words should look like : Interface,GigabitEthernet0/0,"outside",is,up,line,protocol,is,up
            ri.LogicalSystemName = "Default"    
            ri.Name = interfaceName
            status = [i.strip(',') for i in words if "up" in i.lower() or "down" in i.lower()]
            ri.Status = ",".join(status)
          else:
            ri = None
        else:
          if ri:
            # this line belongs to an iterface information block
            sline = line.strip().lower()
            if sline.startswith("ip address"):
              addressAndMask = GetIPAddressAndSubnetMaskFromLine(sline)
              if len(addressAndMask) == 2:
                ri.Address = addressAndMask[0]
                ri.MaskLength = str(IPOperations.GetMaskLength(addressAndMask[1]))
            if sline.startswith("mac address"):
              mac = re.findall(rep_MAC, sline)
              if len(mac) == 1:
                ri.MAC = mac[0]
            if "member of port-channel" in sline:
              lagID = re.findall(r"\d+$", sline)
              if len(lagID) == 1:
                ri.AggregateID = lagID[0]              
        
        # PortMode and VLANS will be processed later in a second pass
      except Exception as Ex:
        DebugEx.WriteLine("CiscoASA.InterfaceParser.ParseInterfaces() : error parsing text {0}. Error is {1}".format(line, str(Ex)))
      
      currentLineIndex += 1
                  
  def GetRoutedInterfaces(self, instance):
    """ Return the list of RouterInterfaces that have a valid IPAddress"""
    # Init interface dictionary for instance
    instanceName = self.Router._defaultRoutingInstanceName
    if instance : instanceName = instance.Name
    if self.Interfaces.get(instanceName, None) == None:
      self.Interfaces[instanceName] = [] 
    # check interface list for this instance
    if len(self.Interfaces[instanceName]) == 0 : 
      self.ParseInterfaces(instance)
    routedInterfaces = filter(lambda x: x.Address, self.Interfaces[instanceName])
    return routedInterfaces
    
  def GetAllInterfaces(self, instance):
    """ Return the list of device interfaces"""
    # Init interface dictionary for instance
    instanceName = self.Router._defaultRoutingInstanceName
    if instance : instanceName = instance.Name
    if self.Interfaces.get(instanceName, None) == None:
      self.Interfaces[instanceName] = [] 
    # check interface list for this instance
    if len(self.Interfaces[instanceName]) == 0 : self.ParseInterfaces(instance)
    return self.Interfaces[instanceName]
    
  def GetInterfaceByASANameIf(self, asaNameif, instance):
    """Returns a RouterInterface object for the interface specified by its ASA nameif property"""        
    # Init interface dictionary for instance
    instanceName = self.Router._defaultRoutingInstanceName
    if instance : instanceName = instance.Name
    if self.Interfaces.get(instanceName, None) == None:
      self.Interfaces[instanceName] = [] 
    # check interface list for this instance
    if len(self.Interfaces[instanceName]) == 0 : self.ParseInterfaces(instance)
    # map ASA namif to interface name
    ifName = self._nameIfs.get(asaNameif.strip(), None)
    if ifName:
      foundInterface = next((intf for intf in self.Interfaces[instanceName] if intf.Name == ifName), None)
    return foundInterface   
    
  def GetInterfaceByName(self, ifName, instance):
    """Returns a RouterInterface object for the interface specified by its name or ASA nameif interface property name"""        
    # Init interface dictionary for instance
    instanceName = self.Router._defaultRoutingInstanceName
    if instance : instanceName = instance.Name
    # initialize instance interfaces if missing
    if self.Interfaces.get(instanceName, None) == None:
      self.Interfaces[instanceName] = [] 
    # check interface list for this instance
    instanceInterfaces = self.Interfaces[instanceName]
    if len(instanceInterfaces) == 0 : 
      self.ParseInterfaces(instance)
      instanceInterfaces = self.Interfaces[instanceName]
    # check if the given ifName is a known ASA namif value
    interfaceByName = self._nameIfs.get(ifName, None)
    if not interfaceByName:
      # not an ASA namif value, so simply use ifName for querying
      interfaceByName = ifName
    foundInterface = next((intf for intf in instanceInterfaces if intf.Name == interfaceByName.strip()), None)
    return foundInterface
    
  def GetInterfaceNameByAddress(self, ipAddress, instance):
    """ Returns a RouterInterface object for the interface specified by its ip address """    
    # Init interface dictionary for instance
    instanceName = self.Router._defaultRoutingInstanceName
    if instance : instanceName = instance.Name
    if self.Interfaces.get(instanceName, None) == None:
      self.Interfaces[instanceName] = [] 
    # check interface list for this instance
    if len(self.Interfaces[instanceName]) == 0 : self.ParseInterfaces(instance)
    ifName = ""
    foundInterface = next((intf for intf in self.Interfaces[instanceName] if intf.Address == ipAddress), None)
    if foundInterface != None:
      ifName = foundInterface.Name
    return ifName 
    
  def GetInterfaceConfiguration(self, ifName):
    """ Return the configuration of an interface """
    if len(self._interfaceConfigurations)  == 0 : self.ParseInterfaceConfigurations()
    # Use interface name without unit name to get full configuration
    # intfName = re.sub(r"\.\d+$", "", ifName)
    ifConfig = self._interfaceConfigurations.get(ifName, "")
    return ifConfig 
    
  def ParseInterfaceConfigurations(self):
    """Gets router running configurtion to collect interface configurations""" 
    # Get running configuration to parse
    if not self._running_config:
      self._running_config = Session.ExecCommand("show running-config interface")
      if len(self._running_config) < 100 and "Command authorization failed" in self._running_config:
        # some systems may not allow running "show run" but still allow "show tech", let's give a try :-)
        tech_support_ipc = Session.ExecCommand("show tech-support")
        temp_running_config = []
        riBlock = False
        for line in tech_support_ipc.splitlines():
          if riBlock:
            if line.find("--- show")  > 0:
              # end of running configuration block
              break
            temp_running_config.append(line)
          else:
            if line.find("--- show running-config ---") > 0:
              # start of running configuration block
              riBlock = True
        self._running_config = "\r\n".join(temp_running_config)
          
    self._interfaceConfigurations = {}
    self._ifNames = {}
    self._nameIfs = {}
    currentIntfName = ""
    currentIntfConfig = []
    runningConfigLines = self._running_config.splitlines()
    lineIndex = 0
    for thisLine in runningConfigLines:
      try:
        words = thisLine.split(" ")
        if thisLine.startswith("interface") and len(words) == 2 :
          # This should be a new interface definition
          if currentIntfName != "":
            # add previous interface
            self._interfaceConfigurations[currentIntfName] = "\r\n".join(currentIntfConfig)
          # Clear current configuration
          currentIntfConfig = []
          currentIntfName = words[1]
        else:
          sline = thisLine.strip(' ')
          if sline != "!" :
           currentIntfConfig.append(sline)
           # region memorize ASA nameif properties
           m = re.findall(r"(?<=nameif ).*", sline)
           if len(m) == 1:
             nameif = m[0].strip()
             self._ifNames[currentIntfName] = nameif
             self._nameIfs[nameif] = currentIntfName
           
      except Exception as Ex:
        message = "CiscoASA.InterfaceParser.ParseInterfaceConfigurations() : could not parse an interface configuration for line <{0}>. Error is : {1} ".format(thisLine, str(Ex))
        DebugEx.WriteLine(message)
      
      lineIndex += 1  
      if lineIndex == len(runningConfigLines) and currentIntfName != "":
          # add last interface
          self._interfaceConfigurations[currentIntfName] = "\r\n".join(currentIntfConfig)       
           
  def IsInterrestingInterface(self, intfName):
    """ Determines if a given name is an interface name we want to parse"""
    iname = intfName.lower()
    return iname.startswith("fastethernet")\
    or iname.startswith("gigabitethernet")\
    or iname.startswith("tengigabitethernet")\
    or iname.startswith("ethernet")\
    or iname.startswith("loopback")\
    or iname.startswith("vlan")\
    or iname.startswith("tunnel")\
    or (iname.startswith("port-channel") and "." in iname)\
    or iname.startswith("management")
      
  def Reset(self) :
    self.Interfaces = {}
    self._interfaceConfigurations = {}
    self._running_config = None
    
  def InterfaceNameToShort(self, longName):
    """Converts a long Cisco interface name to its short representation"""
    inputName = longName.lower()
    shortName = ""
    if inputName.startswith("fastethernet") : shortName = input.replace("fastethernet", "fa")
    elif inputName.StartsWith("tengigabitethernet") : shortName = input.replace("tengigabitethernet", "te")
    elif inputName.StartsWith("gigabitethernet") : shortName = input.replace("gigabitethernet", "gi")
    elif inputName.StartsWith("ethernet") : shortName = input.replace("ethernet", "eth")
    elif inputName.StartsWith("loopback") : shortName = input.replace("loopback", "lo")
    return shortName 
    
  def InterfaceNameToLong(self, shortName):
    """Converts a short Cisco interface name to its long representation"""
    inputName = shortName.lower()
    longName = ""
    if inputName.startswith("fa") and inputName.find("fastethernet") < 0 : longName = inputName.replace("fa", "fastethernet")
    elif inputName.startswith("te") and inputName.find("tengigabitethernet") < 0 : longName = inputName.replace("te", "tengigabitethernet")
    elif inputName.startswith("gi") and inputName.find("gigabitethernet") < 0 : longName = inputName.replace("gi", "gigabitethernet")
    elif inputName.startswith("eth") and inputName.find("ethernet") < 0 :longName = inputName.replace("eth", "ethernet")
    elif inputName.startswith("lo") and inputName.find("loopback") < 0 : longName = inputName.replace("lo", "loopback")
    return longName;
    
    
def GetColumnValue(textLine, headerLine, headerColumn, headerSeparator):
  """Returns the substring from textLine in column determined by the position of position of headerColumn in headerLine"""
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
  
def IP2Int(ip):
  """Converts a string literal ip address to its integer value"""
  try:
    if not ip:
      return -1
    o = map(int, ip.split('.'))
    res = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]
    return res  
  except:
    return -1
  
def GetIPAddressFromLine(line):
  """Extracts the first IP address match from a line of text and returns it
     Expected format is aaa.bbb.ccc.ddd"""
  address = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", line)
  if len(address) == 1 : 
    return address[0]
  else: 
    return "" 
    
def GetIndexedIPAddressFromLine(line, index):
  """Extracts the indexed number IP address match from a line of text and returns it. Index is 1 based.
     Expected format is aaa.bbb.ccc.ddd"""
  addresses = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", line)
  if len(addresses) >= index : 
    return addresses[index-1]
  else: 
    return ""     
    
def GetIPAddressAndSubnetMaskFromLine(line):
  """Extracts the first and second IP address match from a line of text and returns them
     Expected format is aaa.bbb.ccc.ddd"""
  addresses = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", line)
  if len(addresses) >= 2 : 
    return [addresses[0], addresses[1]]
  else: 
    return ""       
  
def GetIPAddressAndMaskFromLine(line):
  """Extracts the first match of an IP address and mask from a line of text and returns it
     Expected format is aaa.bbb.ccc.ddd/xx"""
  address = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/\d{1,2}", line)
  if len(address) == 1 : 
    return address[0]
  else: 
    return ""
    
def GetRegexGroupMatches(pattern, text, groupNum):
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
  ActionResult = CiscoASA()
  ScriptSuccess = True
    