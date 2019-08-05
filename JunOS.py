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
# last changed : 2019.07.24
scriptVersion = "5.3.0"
class JunOS(L3Discovery.IRouter):
  # Beyond _maxRouteTableEntries only the default route will be queried
  _maxRouteTableEntries = 30000    
  def __init__(self):
    # The device version info string
    self._versionInfo = None
    # The device inventory string
    self._inventory = None
    # HostName
    self._hostName = None
    # The DeviceType object determined by GetDeviceType internally
    self._deviceType = DeviceType.Unknown
    # Number of member in a VC
    self._stackCount = 0
    # The list of logical systems defined
    self._logicalSystems = []
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
    self._interfaceParser = InterfaceParser()
    
      
  def GetHostName(self):
    """ Returns the host bane as a string"""
    if not self._hostName : self._hostName = Session.GetHostName()
    return  self._hostName
    
  def GetInventory(self):
    """Returns the device inventory string"""
    if not self._inventory : 
      self._inventory = Session.ExecCommand("show chassis hardware")
    return self._inventory
    
  def GetLogicalSystemNames(self):
    """ Returns the list of Logical Systems as a string list"""
    if len(self._logicalSystems) == 0:
      cmd = "show configuration logical-systems | display set"
      cmdResult = Session.ExecCommand(cmd).lower().splitlines()
      lsLines = [line for line in cmdResult if line.startswith("set logical system")]
      if len(lsLines) == 0 : 
        return ["Default"]
      else :
        repLSs = re.findall(r"(?<=logical-systems ).[a-zA-Z0-9]+", lsLines)
        self._logicalSystems = repLSs
    return self._logicalSystems
    
  def GetManagementIP(self):
    """Returns the management ip address as a string"""
    return ConnectionInfo.DeviceIP
    
  def GetModelNumber(self):
    """Returns Model number as a string, calculated from Inventory"""
    if not self._ModelNumber :
      if self._deviceType == DeviceType.Unknown :
        self.GetDeviceType()      
      inv = self.GetInventory()        
      mn  = ""
      if self._deviceType == DeviceType.Firewall :
        allChassis = re.findall(r"Chassis\s.*", inv)
        for thisChassis in allChassis :
          words = filter(None, thisChassis.split(" "))
          mn += (";" + words[2])
        self._ModelNumber = mn.strip(";")        
      elif self._deviceType == DeviceType.Router :
        allChassis = re.findall(r"Chassis\s.*", inv)
        for thisChassis in allChassis :
          words = filter(None, thisChassis.split(" "))
          mn += (";" + words[2])
        self._ModelNumber = mn.strip(";") 
      elif self._deviceType == DeviceType.Switch :
        FPCs = re.findall(r"FPC \d.*", inv)
        for thisFPC in FPCs :
          words = filter(None, thisFPC.split(" "))
          mn += (";" + words[6])
        self._ModelNumber = mn.strip(";") 
         
    return self._ModelNumber
    
  def GetOperationStatusLabel(self):
    """Returns a string describibg current activity"""
    return self._operationStatusLabel
    
  def GetPlatform(self):
    """Return a string	to describe device Platform"""
    return "JunOS"
    
  def GetSession(self):
    """Returns the actual Session object"""
    # Must return the IScriptableSession this instance is operating on
    return Session
    
  def GetStackCount(self):
    """Returns the number of members in a Virtual Chassis"""
    # Must return an integer
    if self._stackCount == 0 :
      FPCs = re.findall(r"FPC \d.*", Inventory.GetInventory())
      _stackCount = len(FPCs)
    return self._stackCount
    
  def GetSupportTag(self):
    """Returns a string describing capability of this instance"""
    global scriptVersion
    return "Juniper, JunOS, Router Module for EX/QFX/MX/SRX- Python Parser v{0}".format(scriptVersion)
    
  def GetSupportedEngineVersion(self):
    """Returns the regex pattern covering supported Discovery Engine versions"""
    global scriptVersion
    return r"^7\.5.*"
    
  def GetSystemSerial(self):
    """Returns System serial numbers as a string, calculated from Inventory"""
    if not self._SystemSerial :
      if self._deviceType == DeviceType.Unknown :
        self.GetDeviceType()
      inv = self.GetInventory()
      ss = ""
      if self._deviceType == DeviceType.Firewall :
        allChassis = re.findall(r"Chassis\s.*", inv)
        for thisChassis in allChassis :
          words = filter(None, thisChassis.split(" "))
          ss += (";" + words[1])
        self._SystemSerial = ss.strip(";")        
      elif self._deviceType == DeviceType.Router :
        allChassis = re.findall(r"Chassis\s.*", inv)
        for thisChassis in allChassis :
          words = filter(None, thisChassis.split(" "))
          ss += (";" + words[1])
        self._SystemSerial = ss.strip(";") 
      elif self._deviceType == DeviceType.Switch :
        FPCs = re.findall(r"FPC \d.*", inv)
        for thisFPC in FPCs :
          words = filter(None, thisFPC.split(" "))
          ss += (";" + words[5])
        self._SystemSerial = ss.strip(";")
    return self._SystemSerial
    
  def GetDeviceType(self):
    """Returns Type string that can be Switch, Router or Firewall, depending on Model"""
    if self._deviceType == DeviceType.Unknown:
      v = self.GetVersion()
      modelLine = next((line for line in v.splitlines() if "Model:" in line), None)
      if modelLine :
         model = modelLine.split(":")[1].strip()
         if model.startswith("ex") or model.startswith("qfx"): 
           self._deviceType = DeviceType.Switch
         elif model.startswith("srx") : 
           self._deviceType = DeviceType.Firewall
         elif model.startswith("mx") : 
           self._deviceType = DeviceType.Router
         else:
           self._deviceType = DeviceType.Unknown
    
    if self._deviceType == DeviceType.Firewall :
      return "Firewall"     
    elif self._deviceType == DeviceType.Router :
      return "Router" 
    elif self._deviceType == DeviceType.Switch :
      return "Switch" 
    else : 
      return "Unknown"    
    
  def GetVendor(self):
    """Must return a string matching the Vendor name this parser is responible for"""
    return "JunOS"
    
  def GetVersion(self):
    """Must return device version string 	"""
    if not self._versionInfo:
      self._versionInfo = Session.ExecCommand("show version")
    return self._versionInfo
  
  def ActiveProtocols(self, instance):
    """Returns the list of NeighborProtocols running on the requested routing instance """
    instanceName = "master"
    if instance : instanceName = instance.Name
    if self._runningRoutingProtocols.get(instanceName, None) == None:
      self._runningRoutingProtocols[instanceName] = []
    if len(self._runningRoutingProtocols[instanceName]) == 0 :
      # OSPF
      if instanceName.lower() == "master" : 
        cmd = "show ospf overview"
      else :
        cmd = "show ospf overview instance {0}".format(instanceName)
      response = Session.ExecCommand(cmd)
      if (not ("not running" in response)): 
        self._runningRoutingProtocols[instanceName].Add(L3Discovery.NeighborProtocol.OSPF)
      # RIP
      if instanceName.lower() == "master" : 
        cmd = "show rip neighbor"  
      else : 
        cmd = "show rip neighbor instance {0}".format(instanceName)
      response = Session.ExecCommand(cmd)
      if (not ("not running" in response)): 
        self._runningRoutingProtocols[instanceName].Add(L3Discovery.NeighborProtocol.RIP)  
      # BGP
      cmd = "show bgp neighbor instance {0}".format(instanceName)
      response = Session.ExecCommand(cmd)
      if (not ("not running" in response)): 
        self._runningRoutingProtocols[instanceName].Add(L3Discovery.NeighborProtocol.BGP)
      # ISIS
      cmd = "show isis overview instance {0}".format(instanceName)
      response = Session.ExecCommand(cmd)
      if (not ("not running" in response)): 
        self._runningRoutingProtocols[instanceName].Add(L3Discovery.NeighborProtocol.ISIS)
      # STATIC 
      # TODO : "not running" is invalid in this context
      if instanceName.lower() == "master" : 
        cmd = "show configuration routing-options static"  
      else : 
        cmd = "show configuration routing-instances {0} routing-options static".format(instanceName)
      response = Session.ExecCommand(cmd)
      if (not ("not running" in response)): 
        self._runningRoutingProtocols[instanceName].Add(L3Discovery.NeighborProtocol.STATIC)  
      # LLDP - only for default instance
      if instanceName.lower() == "master":
        response = Session.ExecCommand("show lldp")
        lldpenabled = re.findall(r"LLDP\s+:\s+Enabled", response)
        if len(lldpenabled) == 1 : 
          self._runningRoutingProtocols[instanceName].Add(L3Discovery.NeighborProtocol.LLDP)
    return self._runningRoutingProtocols[instanceName]
    
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
    if not self._versionInfo : self._versionInfo = Session.ExecCommand("show version")
    return "junos" in self._versionInfo.lower()
    
  def RegisterNHRP(self, neighborRegistry, instance):
    """Performs NHRP database registration"""
    vrrpSummary = Session.ExecCommand("show vrrp summary")
    if "not running" in vrrpSummary:
      return
    VIPAddress = ""
    GroupID = ""
    PeerAddress = ""
    isActive = False
    ri = None
    for thisLine in vrrpSummary.splitlines():
      try:
        indentLevel = len(thisLine) - len(thisLine.lstrip(' '))
        if indentLevel == 0:
          # interface definition is changing
          if GroupID != "" and VIPAddress != "":
            neighborRegistry.RegisterNHRPPeer(iRouter, instance, ri, L3Discovery.NHRPProtocol.VRRP, isActive, VIPAddress, GroupID, PeerAddress)
            VIPAddress = ""
            GroupID = ""
            PeerAddress = ""
            ri = None
          # -- 
          words = filter(None, thisLine.split(" "))
          if len(words) >= 3 :
            ifName = words[0]
            isActive = "master" in thisLine.lower()
            ri = self.GetInterfaceByName(fName, instance)
            GroupID = words[2]
          continue
        if ri != None:
          words = filter(None, thisLine.split(" "))
          if len(words) == 2:
            role = words[0]
            if role == "lcl" :
              pass
            elif role == "mas" :
              PeerAddress = words[1]
            elif role == "vip" :
              VIPAddress = words[1]
                   
      except Exception as Ex:
        message = "JunOS Router Module Error : could not parse NHRP information <{0}> because : {1} ".format(thisLine, str(Ex))
        DebugEx.WriteLine(message)
        
    # -- register the last one
    if ri != None and VIPAddress != "" and GroupID != "" :
      neighborRegistry.RegisterNHRPPeer(iRouter, instance, ri, L3Discovery.NHRPProtocol.VRRP, isActive, VIPAddress, GroupID, PeerAddress)    
  
  def RegisterTunnels(self, neighborRegistry, instance):
    """Performs registration of active tunnels"""
    # Not implemented for JunOS
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
      # vrf keywords to check
      checkedVRFTags = ["vrf","virtual-router"]
      instances = []
      # Add the default (global) instance
      defInstance = L3Discovery.RoutingInstance()
      defInstance.LogicalSystemName = logicalSystemName
      defInstance.DeviceVendor = "JunOS"
      defInstance.Name = "master"
      instances.append(defInstance)   
      # collect vrf instances, construct CLI command
      model = self.GetModelNumber().lower()
      for vrfTag in checkedVRFTags :
        cmd = "show route instance | match {0}".format(vrfTag)
        if logicalSystemName.lower() != "default":
          cmd = "show route instance operational logical-system {0} | match {1}".format(logicalSystemName, vrfTag)               
        # execute command and parse result
        cmdResult = Session.ExecCommand(cmd)
        instanceNames = c = map(lambda e: e.strip("{0} ".format(vrfTag)), filter(lambda e: not e.startswith("{master"), cmdResult.splitlines()))
        # Add all other instances
        for thisInstanceName in instanceNames:
          thisInstance = L3Discovery.RoutingInstance()
          thisInstance.DeviceVendor = "JunOS"
          thisInstance.LogicalSystemName = logicalSystemName
          thisInstance.Name = thisInstanceName
          instances.append(thisInstance)
      self._routingInstances[logicalSystemName] = instances
      
    return self._routingInstances[logicalSystemName]
    
  def RouteTableSize(self, instance):
    """Returns the size of the route table for the requested routing instance"""
    instanceName = "master"
    if instance : 
      instanceName = instance.Name
    routeTableSize = -1
    cmd = "show route summary table inet.0"
    if instanceName.lower() != "master" : 
      cmd = "show route summary table {0}.inet.0".format(instance.Name)
    routeSummary = Session.ExecCommand(cmd)
    re_destinationCount = re.findall(r"\d+(?= destinations)", routeSummary)
    if len(re_destinationCount) > 0:
      routeTableSize = int(re_destinationCount[0].strip())
    return routeTableSize
      
  def RoutingTable(self, instance):
    """Returns the list of RouteTableEntry objects for requested RoutingInstance"""
    parsedRoutes = []
    instanceName = "master"
    if instance : 
      instanceName = instance.Name
    # get route table size
    routeTableSize = self.RouteTableSize(instance)
    if routeTableSize > self._maxRouteTableEntries :
      # query only default route 
      cmd = "show route 0.0.0.0 inet.0"
      if instanceName.lower() != "master" : cmd = "show route 0.0.0.0 table {0}.inet.0".format(instance.Name)
    else:
      # query inet.0 route table for the requested instance
      cmd = "show route table inet.0"
      if instanceName.lower() != "master" : cmd = "show route table {0}.inet.0".format(instance.Name)
      
    routes = Session.ExecCommand(cmd)
    # define regex expressions for logical text blocks
    networkBlockFilter = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b\/\d{1,2}")
    protocolBlockFilter = re.compile(r"[*[](.*?)\]")
    # network blocks are the top level blocks of the text output, get the iterator for them
    networkBlockIterator = tuple(networkBlockFilter.finditer(routes))
    networkMatchcount = len(networkBlockIterator)
    networkMatchIndex = 0
    # iterate through the network blocks
    for thisNetworkMatch in networkBlockIterator:
      try:
        # thisNetworkMatch is now a MatchObject
        thisNetwork = thisNetworkMatch.group(0)
        # a route block is the text of routes between the position of this match start and the next match start
        routeBlockStart = thisNetworkMatch.start()
        routeBlockEnd = -1
        if (networkMatchIndex == networkMatchcount - 1):
          routeBlockEnd = len(routes)
        else:
          routeBlockEnd = networkBlockIterator[networkMatchIndex + 1].start()
        
        thisRouteBlock = routes[routeBlockStart : routeBlockEnd]      
        # protocol blocks appear inside a network block, get the iterator for them
        protocolBlockIterator = tuple(protocolBlockFilter.finditer(thisRouteBlock))
        # process networks
        protocolMatchcount = len(protocolBlockIterator)
        protocolMatchIndex = 0
        # iterte through the protocol blocks
        for thisProtocolMatch in protocolBlockIterator:
          try:
            # thisProtocolMatch is now a MatchObject
            protocolBlockHeader = thisProtocolMatch.group(0)
            isBestRoute = "*[" in protocolBlockHeader
            protocolBlockStart = thisProtocolMatch.start()
            # a protocol block is the text portion in actual routeBlock between the position of this match start and the next match start
            protocolBlockStart = thisProtocolMatch.start()
            protocolBlockEnd = -1
            if (protocolMatchIndex == protocolMatchcount - 1):
              protocolBlockEnd = len(thisRouteBlock)
            else:
              protocolBlockEnd = protocolBlockIterator[protocolMatchIndex + 1].start()   
            
            thisProtocolBlock =  thisRouteBlock[protocolBlockStart : protocolBlockEnd]
            thisProtocolNames = re.findall(r"[a-zA-Z,-]+", protocolBlockHeader)
            nextHopAddresses = re.findall(r"(?<=to )[\d\.]{0,99}", thisProtocolBlock, re.IGNORECASE)
            routeTags = re.findall(r"(?<=tag )[\d\.]{0,99}", thisProtocolBlock, re.IGNORECASE)
            asPath = re.findall(r"(?<=AS path:).[^,]*",thisProtocolBlock, re.IGNORECASE)
            outInterfaces = re.findall(r"(?<=via ).*", thisProtocolBlock, re.IGNORECASE)
            leartFrom = re.findall(r"(?<=from )[\d\.]{0,99}", thisProtocolBlock, re.IGNORECASE)
            routePreference = re.findall(r"[0-9]+", protocolBlockHeader)
            
            matchIndex = 0
            for thisOutInterface in outInterfaces:
              rte = L3Discovery.RouteTableEntry()
              # Protocol
              if len(thisProtocolNames) == 1 : rte.Protocol = thisProtocolNames[0]
              else : rte.Protocol = "UNKNOWN"
              # RouterID
              rte.RouterID = self._ridCalculator.GetRouterID(rte.Protocol, instance)
              # Prefix and Mask length
              prefixAndMask = thisNetwork.split("/")
              rte.Prefix = prefixAndMask[0]
              rte.MaskLength = int(prefixAndMask[1])
              # OutInterface
              rte.OutInterface = thisOutInterface
              # NextHop address
              if len(nextHopAddresses) > matchIndex : rte.NextHop = nextHopAddresses[matchIndex]
              else : rte.NextHop = ""
              # LeartFrom
              if len(leartFrom) == 1 : rte.From = leartFrom[0]
              else : rte.From = ""
              # Prefix parameters
              rte.Best = isBestRoute
              if len(routeTags) == 1 : rte.Tag = routeTags[0]
              else : rte.Tag = ""
              if len(routePreference) == 1 : rte.AD = routePreference[0]
              else : rte.AD = ""
              if len(asPath) == 1 : rte.ASPath = asPath[0]
              else : rte.ASPath = ""
              rte.Community = ""
              rte.Metric = ""
              parsedRoutes.Add(rte)
              matchIndex += 1
                   
            protocolMatchIndex += 1
          except Exception as Ex:
            message = "JunOS Router Module Error : could not parse a route table Protocol block because : " + str(Ex)
            DebugEx.WriteLine(message)   
        
        networkMatchIndex += 1
      except Exception as Ex:
        message = "JunOS Router Module Error : could not parse a route table Network block because : " + str(Ex)
        DebugEx.WriteLine(message)
      
    return parsedRoutes
    
class RouterIDCalculator():
  """Performs Router ID and AS Number calculations """
  def __init__(self, router):
    # self.Router will hold a reference to the JunOS router instance
    self.Router = router
    # RouterID is a dictionary in dictionary, outer keyed by RoutingInstance name, inner keyed by RoutingProtocol as a string
    self.RouterID = {}
    # BGPASNumber is a dictionary, keyed by RoutingInstance name
    self.BGPASNumber = {}  
    
  def GetRouterID(self, protocol, instance):
    """Return the RouterID for given instance and protocol"""
    rid = ""
    instanceName = "master"
    if instance : instanceName = instance.Name
    if len(self.RouterID.get(instanceName, {})) == 0 : self.CalculateRouterIDAndASNumber(instance)
    instanceRIDs = self.RouterID.get(instanceName, None)
    if instanceRIDs != None:
      rid = instanceRIDs.get(str(protocol), "")
    return rid
    
  def GetBGPASNumber(self, instance):
    instanceName = "master"
    if instance : instanceName = instance.Name
    if len(self.BGPASNumber) == 0 : 
      self.CalculateRouterIDAndASNumber(instance)
    return self.BGPASNumber.get(instanceName, "")
    
  def CalculateRouterIDAndASNumber(self, instance):
    """Parse the RouterID and AS number for the requested RoutingInstance"""  
    instanceName = "master"
    if instance : instanceName = instance.Name
    if self.RouterID.get(instanceName, None) == None: self.RouterID[instanceName] = {}
    
    # Global router ID is a the router ID of the most preferred routing protocol
    globalRouterID = ConnectionInfo.DeviceIP
    
    cmd = "show configuration routing-options"
    if instanceName.lower() != "master" : cmd = "show configuration routing-instances {0} routing-options".format(instanceName)
    routingOptions = Session.ExecCommand(cmd)
    rid = re.findall(r"(?<=router-id )[\d.]{0,99}", routingOptions)
    if len(rid) > 0 : globalRouterID = rid[0]
    # get the running routing protocols for this routing instance
    runningRoutingProtocols = self.Router.ActiveProtocols(instance)
    # sort the routing protocols by preference (its integer value)
    sRoutingProtocols = sorted(runningRoutingProtocols, key=lambda p: int(p))
    for thisProtocol in sRoutingProtocols:  
      if thisProtocol == L3Discovery.NeighborProtocol.BGP:
        # init dictionary for protocol if empty
        if self.RouterID[instanceName].get(str(thisProtocol), None) == None: self.RouterID[instanceName][str(thisProtocol)] = {}
        # construct CLI command
        cmd = "show bgp neighbor instance {0}".format(instanceName)
        bgpNeighbors = Session.ExecCommand(cmd)
        # execute CLI command and parse result
        rid = re.findall(r"(?<=Local ID: )[\d.]{0,99}", bgpNeighbors)
        if len(rid) > 0 : self.RouterID[instanceName][str(thisProtocol)] = rid[0]
        elif globalRouterID != "" : self.RouterID[instanceName][str(thisProtocol)] = globalRouterID
        # get AS number
        if self.BGPASNumber.get(instanceName, None) == None: self.BGPASNumber[instanceName]= ""
        ASes = re.findall(r"(?<=AS )[\d.]{0,99}",  bgpNeighbors)
        if len(ASes) >= 2 : self.BGPASNumber[instanceName] = ASes[1]
        else : 
          ASes = re.findall(r"(?<=autonomous-system )[\d.]{0,99}", routingOptions)
          if len(ASes) > 0 : self.BGPASNumber[instanceName] = ASes[0]
        
      elif thisProtocol == L3Discovery.NeighborProtocol.OSPF:
        # init dictionary for protocol if empty
        if self.RouterID[instanceName].get(str(thisProtocol), None) == None: self.RouterID[instanceName][str(thisProtocol)] = {}
        # construct CLI command
        cmd = "show ospf overview"
        if instanceName.lower() != "master" : cmd += " instance {0}".format(instanceName)
        # execute CLI command and parse result
        ospfStatus = Session.ExecCommand(cmd)
        rid = re.findall(r"(?<=Router ID: )[\d.]{0,99}", ospfStatus)
        if len(rid) > 0 : self.RouterID[instanceName][str(thisProtocol)] = rid[0].strip()
        elif globalRouterID != "" : self.RouterID[instanceName][str(thisProtocol)] = globalRouterID
        
      elif thisProtocol == L3Discovery.NeighborProtocol.ISIS:
        # init dictionary for protocol if empty
        if self.RouterID[instanceName].get(str(thisProtocol), None) == None: self.RouterID[instanceName][str(thisProtocol)] = {}
        # construct CLI command
        cmd = "show isis overview"
        if instanceName.lower() != "master" : cmd += " instance {0}".format(instanceName)
        # execute CLI command and parse result
        isisStatus = Session.ExecCommand(cmd)
        rid = re.findall(r"(?<=Sysid:).+", isisStatus, re.IGNORECASE)
        if len(rid) > 0 : self.RouterID[instanceName][str(thisProtocol)] = rid[0].strip()
        elif globalRouterID != "" : self.RouterID[instanceName][str(thisProtocol)] = globalRouterID      
        
      elif thisProtocol == L3Discovery.NeighborProtocol.LLDP:
        # init dictionary for protocol if empty
        if self.RouterID[instanceName].get(str(thisProtocol), None) == None: self.RouterID[instanceName][str(thisProtocol)] = {}
        # only for default (global) routing instance
        if instanceName.lower() == "master" :
          # execute CLI command and parse result
          lldpInfo = Session.ExecCommand("show lldp local-information")
          lldpStatus = re.findall(r"(?:Chassis ID\s+: )([0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+)", lldpInfo)
          if len(lldpStatus) > 0 : self.RouterID[instanceName][str(thisProtocol)] = lldpStatus[0]
      elif thisProtocol == L3Discovery.NeighborProtocol.RIP:
        # init dictionary for protocol if empty
        if self.RouterID[instanceName].get(str(thisProtocol), None) == None: self.RouterID[instanceName][str(thisProtocol)] = {}
        # always use global router-id
        # TODO : this may require tuning
        self.RouterID[instanceName][str(thisProtocol)] = globalRouterID       
        
      elif thisProtocol == L3Discovery.NeighborProtocol.STATIC:  
        # init dictionary for protocol if empty
        if self.RouterID[instanceName].get(str(thisProtocol), None) == None: self.RouterID[instanceName][str(thisProtocol)] = {}
        # always use global router-id
        self.RouterID[instanceName][str(thisProtocol)] = globalRouterID 
        
      else :
        self.RouterID[instanceName][str(thisProtocol)] = globalRouterID   
          
  def Reset(self):
    self.RouterID = {}
    self.BGPASNumber = {}
    
class InterfaceSpan():
  """A span of two Interfaces"""
  fromPIC = 0
  fromFPC = 0
  fromPort = 0
  toPIC = 0
  toFPC = 0
  toPort = 0
  
  def __init__(self, fromInterfaceName, toInterfaceName) :
    """Initialize a new SwithInterfaceSpan by defining the from and to interface names"""
    self.fromSwitchInterface = fromInterfaceName
    f = re.findall(r"\d+", fromInterfaceName.split(".")[0])
    if len(f) == 3 :
      self.fromFPC = int(f[0])
      self.fromPIC = int(f[1])
      self.fromPort = int(f[2])
    else:
      raise ValueError("FromInterface name is invalid")
    self.toSwitchInterface = toInterfaceName
    t = re.findall(r"\d+", toInterfaceName.split(".")[0])
    if len(t) == 3 :
      self.toFPC = int(t[0])
      self.toPIC = int(t[1])
      self.toPort = int(t[2])
    else:
      raise ValueError("ToInterface name is invalid")
    
  def IsInterfaceInRange(self, testSwitchInterface):
    t = re.findall(r"\d+", testSwitchInterface.split(".")[0])
    if len(t) == 3:
      testFPC = int(t[0])
      testPIC = int(t[1])
      testPort = int(t[2])
      matched = testFPC >= self.fromFPC and  testFPC <= self.toFPC and testPIC >= self.fromPIC and testPIC <= self.toPIC and testPort >= self.fromPort and testPort <= self.toPort  
      return matched
    else:
      return False
  
class InterfaceRange():
  """Manifests a Juniper specific Interface-Range definition"""
  rangeName = ""
  # The list of SwithInterfaceSpans for this range definition
  rangeSpans = []
  portMode = ""
  vlanMembers = []
  
  def __init__(self, rangeName) :
    """Initialize a new SwithInterfaceRange object by range name"""
    self.rangeName = rangeName
    self.rangeSpans = []
    self.vlanMembers = []
  
  def AddInterfaceSpan(self, fromInterfaceName, toInterfaceName):
    """Adds a new SwitchInterfaceSpan to the range definition"""
    self.rangeSpans.append(InterfaceSpan(fromInterfaceName, toInterfaceName))
    
  def IsInterfaceInRange(self, testSwitchInterface):
    """Determines if a given SwitchInterface belongs to the range definition"""
    return any(map(lambda r : r.IsInterfaceInRange(testSwitchInterface), self.rangeSpans))
    
    
class InterfaceParser(): 
  """Manage JunOS interfaces"""
  def __init__(self):
      # These are the interfaces collected by ParseInterfaces() method. A dictionary, keyed by routing instance name
    self.Interfaces = {}
    # All interfaces configuration. Unparsed, as returned by CLI command
    self.AllInterfaceConfiguration = ""
    # Interface config cache. A dictionary keyed by Interface Name
    self._interfaceConfigurations = {}
    # VLAN config cache containing VLAN names and id-s, keyed by vlan name
    self._vlanNames = {}
    # VLAN config cache containing VLAN names and id-s, keyed by vlan-id
    self._vlanIDs = {}
    # List of interface-ranges    
    self.InterfaceRanges = []
    
  def ParseInterfaces(self, instance) :
    """Collects interface details for all interfaces of specified routing instance, but do not collect interface configuration """
    # Get interface range definitions
    if len(self.InterfaceRanges) == 0 : self.ParseInterfaceRanges()
    # Get the interfaces configuration
    if self.AllInterfaceConfiguration == "" : self.ParseInterfaceConfigurations()
    # Init interface dictionary for instance
    instanceName = "master"
    if instance : instanceName = instance.Name
    if self.Interfaces.get(instanceName, None) == None:
      self.Interfaces[instanceName] = [] 
    # Query the device interfaces
    if instanceName.lower() != "master" : 
      interfaces = Session.ExecCommand("show interfaces routing-instance {0} terse".format(instanceName)).splitlines()
    else :
      interfaces = Session.ExecCommand("show interfaces terse").splitlines()
    
    # Because JunOS reports the VRRP VIP addresses in "show interface terse" output, it is necessary to 
    # check interface ip of VRRP enabled interfaces
    if instanceName.lower() != "master" :
      vrrpSummary = Session.ExecCommand("show vrrp logical-system {0} summary | match lcl".format(instance.LogicalSystemName)).splitlines()
    else:
      vrrpSummary = Session.ExecCommand("show vrrp summary | match lcl").splitlines()
    # Parse the result and fill up self.Interfaces list
    for line in interfaces:  
      words = filter(None, line.split(" "))
      ifName = words[0]
      intfLun = re.findall(r"\.\d+$", ifName)
      if self.IsInterrestingInterface(ifName):
        ri = L3Discovery.RouterInterface()
        ri.Name = ifName
        ri.Address = ""
        ri.MaskLength = ""
        ri.Status =  "{0},{1}".format(words[1], words[2])
        ri.VRFName = instanceName
        if len(words) >= 4:
          ifProtocol = words[3]
          # ifProtocol could be inet, eth-switch, aenet
          if ifProtocol == "inet" and len(words) >= 5:
            # words should look like : xe-0/0/25.0,up,up,inet,172.20.1.18/31 
            ifIPAndMask = words[4].Split("/")
            # create a reference variable to pass it to TryParse (this is an out parameter in .Net)
            ipa = clr.Reference[IPAddress]()
            # check if this is a valid ip address
            if IPAddress.TryParse(ifIPAndMask[0], ipa):
              ri.PortMode = L3Discovery.RouterInterfacePortMode.Routed
              # check if VRRP runs on interface
              vrrpLine = next((line for line in vrrpSummary if line.startswith(ifName)), None)
              if vrrpLine != None:
                # VRRP is running on interface, use the lcl address
                # Address should be the last word
                vrrpLineWords = filter(None, vrrpLine.split(" "))
                ri.Address = vrrpLineWords[len(vrrpLineWords)-1]
              else :
                # VRRP is not running on interface, use address from "show interface terse"
                ri.Address = ifIPAndMask[0]
              if len(ifIPAndMask) >= 2 : ri.MaskLength = ifIPAndMask[1]
              else : ri.MaskLength = ""
              ri.Configuration = self.GetInterfaceConfiguration(ri.Name)
              self.Interfaces[instanceName].Add(ri) 
              # If this is a logical unit, we may be facing with an L3 subinterface
              if len(intfLun) == 1:
                phIntfName = re.sub(r"\.\d+$", "", ri.Name)
                phri = next((intf for intf in self.Interfaces[instanceName] if intf.Name == phIntfName), None)
                if phri != None:
                  # Lets check if vlan-tagging has been configured on physical interface
                  if phri.Configuration and ("vlan-tagging" in phri.Configuration or "flexible-vlan-tagging" in phri.Configuration):
                    # vlan tagging is enabled, so this ius an L3 subinterface
                    phri.PortMode = L3Discovery.RouterInterfacePortMode.L3Subinterface
                    if phri.VLANS == None : existingVLANs = []
                    else : existingVLANs = filter(None, phri.VLANS.split(","))
                    # Get vlan-id from configuration. If not found, assume lun number equals to the VLAN ID
                    m_vlanID = re.findall(r"(?<=vlan-id )\d+", ri.Configuration)
                    if len(m_vlanID) == 1 : 
                      VLANID = m_vlanID[0]
                      existingVLANs.append(self.FormatVLANSEntry(VLANID))
                      phri.VLANS = ",".join(existingVLANs) 
                  else:
                    # vlan tagging is enabled, so this ius an L3 subinterface
                    phri.PortMode = L3Discovery.RouterInterfacePortMode.Routed
                        
          elif ifProtocol == "eth-switch" :
            # words should look like : ge-3/0/36.0,up,up,eth-switch        
            ri.Configuration = self.GetInterfaceConfiguration(ri.Name)
            ri.PortMode = L3Discovery.RouterInterfacePortMode.Access
            if ri.Configuration:
              # We have explicit port configuration 
              # First get port mode
              pm = re.findall(r"(?<=port-mode )[^;]+", ri.Configuration, re.IGNORECASE)
              if len(pm) == 1:
                mode = pm[0].strip().lower()
                if mode == "access" : ri.PortMode =  L3Discovery.RouterInterfacePortMode.Access
                elif mode == "trunk" : ri.PortMode =  L3Discovery.RouterInterfacePortMode.Trunk
              else :
                pm = re.findall(r"(?<=interface-mode )[^;]+", ri.Configuration, re.IGNORECASE)
                if len(pm) == 1:
                  mode = pm[0].strip().lower()
                  if mode == "access" : ri.PortMode =  L3Discovery.RouterInterfacePortMode.Access
                  elif mode == "trunk" : ri.PortMode =  L3Discovery.RouterInterfacePortMode.Trunk
                else : 
                  # Default to access mode
                  ri.PortMode =  L3Discovery.RouterInterfacePortMode.Access
              # Then get VLANs
              vlans = re.findall(r"(?<=members )\[?([\s\w\-]+)", ri.Configuration, re.IGNORECASE)
              if len(vlans) == 1 : 
                vlanList = filter(None, vlans[0].strip().split(" "))
                # assume vlanList contain  either vlanIDs or vlanNames
                formattedVLANList = map(lambda f: self.FormatVLANSEntry(f), vlanList)
                ri.VLANS = ",".join(formattedVLANList)
              self.Interfaces[instanceName].Add(ri)   
              # If this is a logical unit, let the physical interface inherit properties
              if len(intfLun) == 1:
                phIntfName = re.sub(r"\.\d+$", "", ri.Name)
                phri = next((intf for intf in self.Interfaces[instanceName] if intf.Name == phIntfName), None)
                if phri != None:
                  phri.PortMode = ri.PortMode
                  phri.VLANS = ri.VLANS
                  phri.Status = ri.Status
            else:
              # Do not have explicit port configuration , check InterfaceRanges
              phIntfName = re.sub(r"\.\d+$", "", ri.Name)
              ir = next((ir for ir in self.InterfaceRanges if ir.IsInterfaceInRange(phIntfName)), None)
              if ir != None:
                # Found the interface in a range, inherit range properties
                if ir.portMode == "access" : ri.PortMode =  L3Discovery.RouterInterfacePortMode.Access
                elif ir.portMode == "trunk" : ri.PortMode =  L3Discovery.RouterInterfacePortMode.Trunk
                ri.VLANS = ",".join(ir.vlanMembers)
              
          elif ifProtocol == "aenet" :
            # words should look like : xe-3/0/44.0,up,up,aenet,-->,ae3.0      
            ri.AggregateID = words[5]
            ri.Configuration = self.GetInterfaceConfiguration(ri.Name)
            # PortMode and VLANS will be processed later in a second pass
            self.Interfaces[instanceName].Add(ri)       
             
        elif len(words) == 3:      
          # This is the physical interface. Might be unconfigured
          # words should look like : ge-3/0/36.0,up,up        
          ri.Configuration = self.GetInterfaceConfiguration(ri.Name)
          if ri.Configuration:
            # in some cases JunOS forgets to report the interface as "aenet" in "show interfaces terse" output, therefore we perform this step
            re_aggID = re.findall(r"(?<=802.3ad)[\s\d\w]+", ri.Configuration, re.IGNORECASE)
            if len(re_aggID) == 1:
              ri.AggregateID = re_aggID[0].strip()
          self.Interfaces[instanceName].Add(ri)  
          
    # Post-process aenet interfaces to inherit VLANs and portMode from aggregate interface
    aggregatedInterfaces = [intf for intf in self.Interfaces[instanceName] if intf.AggregateID]
    for thisAaggregatedInterface in aggregatedInterfaces:
      aggregatorInterface = next((intf for intf in self.Interfaces[instanceName] if intf.Name == thisAaggregatedInterface.AggregateID), None)
      if aggregatorInterface != None:
        
        thisAaggregatedInterface.VLANS = aggregatorInterface.VLANS
        thisAaggregatedInterface.PortMode = aggregatorInterface.PortMode
        
    # Process descriptions
    if instanceName.lower() != "master" : 
      interfaceDescriptions = Session.ExecCommand("show interfaces routing-instance {0} descriptions".format(instanceName)).splitlines()
    else :
      interfaceDescriptions = Session.ExecCommand("show interfaces descriptions").splitlines()
    for line in interfaceDescriptions:
      words = filter(None, line.split(" "))
      if len(words) >= 4:
        ifName = words[0]
        foundInterface = next((intf for intf in self.Interfaces[instanceName] if intf.Name == ifName), None)
        if foundInterface != None : foundInterface.Description = " ".join([t for t in words if words.index(t) >= 3])
     
  def FormatVLANSEntry(self, expression):
    """Constructs the formated VLANS lsit entry from vlanName or vlanID. If VLANName to vlan-id assignment exists returns like VLANName|VLANID or if not, simply expression itself"""
    if not self._vlanNames or len(self._vlanNames) == 0 :
      self._vlanNames = {}
      self._vlanIDs = {}
      vlanInfo = Session.ExecCommand("show vlans")
      # get regex matches group 1
      vlanNames = GetRegexGroupMatches(r"\s+(\S+)\s+(\d+)", vlanInfo, 1)
      # get regex matches group 2
      vlanIDs = GetRegexGroupMatches(r"\s+(\S+)\s+(\d+)", vlanInfo, 2)
      if len(vlanNames) == len(vlanIDs):     
        for index in range(0, len(vlanNames)) :
          self._vlanNames[vlanIDs[index]] = vlanNames[index].strip()
          self._vlanIDs[vlanNames[index]] = vlanIDs[index].strip()
      else:
        # do not throw error but log the error
        DebugEx.WriteLine("JunOS.FormatVLANSEntry() : error, unable to extract VLAN IDs and Names. Got different number of vlan-ids than vlan names.")   
    if len(self._vlanNames) > 0 :
      # assume expression is a vlan name and check if we can find vlan-id by this name
      vlanID = self._vlanIDs.get(expression, None)
      if vlanID:
        return "{0}|{1}".format(expression, vlanID)
      else:
        # assume expression a vlan-id and check if we can find vlan Name by id
        vlanName = self._vlanNames.get(expression, None)
        if vlanName :
          return "{0}|{1}".format(vlanName, expression)
        else:
          return expression
    else :
      return expression
    
  def GetRoutedInterfaces(self, instance):
    """ Return the list of RouterInterfaces that have a valid IPAddress"""
    # Init interface dictionary for instance
    instanceName = "master"
    if instance : instanceName = instance.Name
    if self.Interfaces.get(instanceName, None) == None:
      self.Interfaces[instanceName] = [] 
    # check interface list for this instance
    if len(self.Interfaces[instanceName]) == 0 : self.ParseInterfaces(instance)
    routedInterfaces = filter(lambda x: x.Address != "", self.Interfaces[instanceName])
    return routedInterfaces
  def GetAllInterfaces(self, instance):
    """ Return the list of device interfaces"""
    # Init interface dictionary for instance
    instanceName = "master"
    if instance : instanceName = instance.Name
    if self.Interfaces.get(instanceName, None) == None:
      self.Interfaces[instanceName] = [] 
    # check interface list for this instance
    if len(self.Interfaces[instanceName]) == 0 : self.ParseInterfaces(instance)
    return self.Interfaces[instanceName]
    
  def GetInterfaceByName(self, ifName, instance):
    """Returns a RouterInterface object for the interface specified by its name"""        
    # Init interface dictionary for instance
    instanceName = "master"
    if instance : instanceName = instance.Name
    if self.Interfaces.get(instanceName, None) == None:
      self.Interfaces[instanceName] = [] 
    # check interface list for this instance
    if len(self.Interfaces[instanceName]) == 0 : self.ParseInterfaces(instance)
    foundInterface = next((intf for intf in self.Interfaces[instanceName] if intf.Name == ifName.strip()), None)
    return foundInterface
    
  def GetInterfaceNameByAddress(self, ipAddress, instance):
    """ Returns a RouterInterface object for the interface specified by its ip address """    
    # Init interface dictionary for instance
    instanceName = "master"
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
    if self.AllInterfaceConfiguration == "" : self.ParseInterfaceConfigurations()
    # Use interface name without unit name to get full configuration
    # intfName = re.sub(r"\.\d+$", "", ifName)
    ifConfig = self._interfaceConfigurations.get(ifName, "")
    return ifConfig 
  def ParseInterfaceConfigurations(self):
    """ Executes CLI command to query all interfaces configuration from device """  
    self.AllInterfaceConfiguration = Session.ExecCommand("show configuration interfaces")
    # Clear configuration dictionary
    self._interfaceConfigurations = {}
    currentIntfName = ""
    currentConfiguration = []
    for thisLine in self.AllInterfaceConfiguration.splitlines():
      try:
        if thisLine == "}" :  continue
        lineindent = len(thisLine) - len(thisLine.strip())
        if lineindent == 0 :
          # This should be a new interface
          if currentIntfName != "":
            # Need to separate by units
            unitName = ""
            logicalInterfaceConfiguration = []
            for confLine in currentConfiguration:
              if confLine.strip().startswith("unit"):
                # This should be a new unit
                if unitName == "":
                  # This is the physicyl interface
                  self._interfaceConfigurations[currentIntfName] = "\r\n".join(logicalInterfaceConfiguration)
                else:
                  # Add current logical interface to _interfaceConfigurations
                  unitNumber = re.findall(r"\d+", unitName)[0]
                  logicalIntfName = currentIntfName + "." + unitNumber
                  self._interfaceConfigurations[logicalIntfName] = "\r\n".join(logicalInterfaceConfiguration)
                if "{" in confLine:
                  unitName =  confLine[0:confLine.index("{")].strip()
                elif ";" in confLine:
                  unitName =  confLine[0:confLine.index(";")].strip()
                logicalInterfaceConfiguration = []
              else:
                logicalInterfaceConfiguration.append(confLine)
            # Add the last physical/logical interface to _interfaceConfigurations
            if unitName != "":
              unitNumber = re.findall(r"\d+", unitName)[0]
              logicalIntfName = currentIntfName + "." + unitNumber
              self._interfaceConfigurations[logicalIntfName] = "\r\n".join(logicalInterfaceConfiguration)   
            else:
              self._interfaceConfigurations[currentIntfName] = "\r\n".join(currentConfiguration)   
          if "{" in thisLine:
            currentIntfName = thisLine[0:thisLine.index("{")].strip()
          elif ";" in thisLine:
            currentIntfName = thisLine[0:thisLine.index(";")].strip()
          # Validate what we got
          if not self.IsInterrestingInterface(currentIntfName) : 
            currentIntfName = ""
          # Clear current configuration
          currentConfiguration = []
        else:
          currentConfiguration.append(thisLine)
      except Exception as Ex:
        message = "JunOS Router Module Error : could not parse an interface configuration for line <{0}>. Error is : {1} ".format(thisLine, str(Ex))
        DebugEx.WriteLine(message)   
  def ParseInterfaceRanges(self):
    """ Parse out the interface range definitions from device"""
    ranges = Session.ExecCommand("show configuration interfaces | display set | match interface-range")
    for line in [l.lower().strip() for l in ranges.splitlines()] :
      try:
        words = line.split(" ")
        if "interface-range" in line :
          if " member-range " in line :
            # line is like : set interfaces interface-range WORKSTATION-IP-PHONE member-range ge-0/0/0 to ge-0/0/41
            # add ranges
            rangeName = words[3]
            fromInterfaceName = words[5]
            toInterfaceName = words[7]
            # find if already a defined range
            foundRange = next((ir for ir in self.InterfaceRanges if ir.rangeName == rangeName), None)
            if foundRange != None : 
              foundRange.AddInterfaceSpan(fromInterfaceName, toInterfaceName)
            else:
              newRange = InterfaceRange(rangeName)
              newRange.AddInterfaceSpan(fromInterfaceName, toInterfaceName)
              self.InterfaceRanges.append(newRange)  
          elif " member " in line :
              # line is like : set interfaces interface-range WORKSTATION-IP-PHONE member ge-0/0/0
              # add ranges
              rangeName = words[3]
              fromInterfaceName = words[5]
              toInterfaceName = words[5]
              # find if already a defined range
              foundRange = next((ir for ir in self.InterfaceRanges if ir.rangeName == rangeName), None)
              if foundRange != None : 
                foundRange.AddInterfaceSpan(fromInterfaceName, toInterfaceName)
              else:
                newRange = InterfaceRange(rangeName)
                newRange.AddInterfaceSpan(fromInterfaceName, toInterfaceName)
                self.InterfaceRanges.append(newRange)   
          else :
            rangeName = words[3]
            # find a defined range (should aready be in the list)
            foundRange = next((ir for ir in self.InterfaceRanges if ir.rangeName == rangeName), None)
            if foundRange != None : 
              # set interface properties for ranges
              if "interface-mode" in line :
                # line is like : set interfaces interface-range WORKSTATION-IP-PHONE unit 0 family ethernet-switching interface-mode access
                foundRange.portMode = words[len(words) - 1]         
              elif "port-mode" in line :
                # line is like : set interfaces interface-range WORKSTATION-IP-PHONE unit 0 family ethernet-switching interface-mode access
                foundRange.portMode = words[len(words) - 1] 
              elif "vlan members" in line :
                # line is like : set interfaces interface-range WORKSTATION-IP-PHONE unit 0 family ethernet-switching vlan members Corp-Access
                foundRange.vlanMembers.append(words[len(words) - 1])
            else:
              raise Exception("Interface range name <{0}> definition is missing".format(rangeName))
    
      except Exception as Ex:
        message = "JunOS Router Module Error : could not parse an interface range for line <{0}>. Error is : {1} ".format(line, str(Ex))
        DebugEx.WriteLine(message)   
   
    pass
    
  def IsInterrestingInterface(self, intfName):
    """ Determines if a given name is an interface name we want to parse"""
    return intfName.startswith("ge-") or intfName.startswith("xe-") or intfName.startswith("et-") or intfName.startswith("ae") or intfName.startswith("irb") or intfName.startswith("vlan") or intfName.startswith("lo")
      
  def Reset(self) :
    self.Interfaces = {}
    self.AllInterfaceConfiguration = ""
    self.InterfaceRanges = []
    self._vlanNames = {}
    self._vlanIDs = {}
"""Juniper Device Type"""
class DeviceType:
  Unknown = 0
  Switch = 1
  Router = 2
  Firewall = 4
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
    
################### Script entry point ###################
if ConnectionInfo.Command == "CreateInstance":
  ActionResult = JunOS()
  ScriptSuccess = True
    