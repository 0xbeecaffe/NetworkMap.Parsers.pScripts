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
# last changed : 2019.04.09
scriptVersion = "5.0.5"
class CiscoIOSRouter(L3Discovery.IRouter):
  # Beyond _maxRouteTableEntries only the default route will be queried
  _maxRouteTableEntries = 30000    
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
        self._ModelNumber = models[0]
      else:
        self._ModelNumber = "n/a"
    return self._ModelNumber
    
  def GetOperationStatusLabel(self):
    """Returns a string describibg current activity"""
    return self._operationStatusLabel
    
  def GetPlatform(self):
    """Return a string	to describe device Platform"""
    return "IOS"
    
  def GetSession(self):
    """Returns the actual Session object"""
    return Session
    
  def GetStackCount(self):
    """Returns the number of members in a switch stack"""
    if self._stackCount == 0 :
      stackedswitches = Session.ExecCommand("show switch")
      members = re.findall(r"^[*\s]{2}\d{1,2}", stackedswitches)
      self._stackCount = len(members)
    return self._stackCount
    
  def GetSupportTag(self):
    """Returns a string describing capability of this instance"""
    global scriptVersion
    return "Cisco, IOS Router support module - Python Parser v{0}".format(scriptVersion)
    
  def GetSystemSerial(self):
    """Returns System serial numbers as a string, calculated from Inventory"""
    if not self._SystemSerial :
      ss = ""
      # first try to check inventory for serial numbers
      inv = self.GetInventory()
      failwords = self.ScriptSettings.FailedCommandPattern.split(";")
      if any(fw in inv for fw in failwords) or "invalid input" in inv.lower():
        # show inventory did not work, try to parse version information for system serial number
        DebugEx.WriteLine("CiscoIOSRouter : router does not support \"show inventory\" command, parsing version information", DebugLevel.Debug)
        r_serial = re.findall(r"(?<=System serial number : ).*", self.GetVersion(), re.IGNORECASE)
        if len(r_serial) > 0:
          self._SystemSerial = r_serial[0]
        
      else:
        if self.GetStackCount() > 0 :
          modules = Session.ExecCommand("show module")
          if any(fw in modules for fw in failwords) or "invalid input" in modules.lower():
            # show module did not work, try to parse version information to get system serial numbers
            DebugEx.WriteLine("CiscoIOSRouter : router does not support \"sh module\" command, parsing version information", DebugLevel.Debug)
            r_serial = re.findall(r"(?<=System serial number : ).*", self.GetVersion(), re.IGNORECASE)
            if len(r_serial) > 0:
              self._SystemSerial = r_serial[0]
          else:
            # try to parse sh_version to get system serial numbers
            # TODO : missing command output sample to process
            pass  
        else:
          SNs = re.finditer(r"(?<=SN: ).*", inv, re.MULTILINE)
          self._SystemSerial = ",".join([SN.group() for matchNum, SN in enumerate(SNs, start=1)])
      FPCs = re.findall(r"FPC \d.*", inv)
      for thisFPC in FPCs :
        words = filter(None, thisFPC.split(" "))
        ss += (";" + words[5])
      self._SystemSerial = ss.strip(";")
    return self._SystemSerial
    
  def GetDeviceType(self):
    """Returns Type string that can be Switch, Router or Firewall, depending on Model"""
    m = self.GetModelNumber()
    if m.startswith("2") : return "Switch"
    else : return "Router"
    
  def GetVendor(self):
    """Must return a string matching the Vendor name this parser is responible for"""
    return "Cisco"
    
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
      cmd = "show ip route static"
      if instanceName != defaultInstanceName:
        cmd = "show ip route vrf {0} static".format(instanceName)
      response = Session.ExecCommand(cmd);  
      if response : 
        self._runningRoutingProtocols[instance.Name].append(NeighborProtocol.STATIC)  
        
 
      # CDP - only for default instance
      if instanceName == defaultInstanceName:
        response = Session.ExecCommand("show cdp")
        cdpEnabled = not ("not enabled" in response)
        if cdpEnabled: 
          self._runningRoutingProtocols[instanceName].Add(NeighborProtocol.CDP)
          
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
    return "cisco ios" in v.lower()
    
  def RegisterNHRP(self, neighborRegistry, instance):
    """Performs NHRP database registration"""
    # neighborRegistry :The NetworkRegistry object
    # instance :The Routing instance reference
    # 
    # Sample input for parsing
    #
    #GigabitEthernet0/0/1 - Group 44
    #  State is Active
    #	  5 state changes, last state change 4w4d
    #  Virtual IP address is 10.81.0.1
    #  Active virtual MAC address is 0000.0c07.ac2c(MAC In Use)
    #	  Local virtual MAC address is 0000.0c07.ac2c(v1 default)
    #  Hello time 1 sec, hold time 3 sec
    #	  Next hello sent in 0.256 secs
    #  Authentication text, string "ROWVA252"
    #  Preemption enabled, delay min 60 secs
    #  Active router is local
    #  Standby router is 10.81.0.3, priority 100 (expires in 3.040 sec)
    #  Priority 105 (configured 105)
    #			Track object 1 state Up decrement 10
    #  Group name is "hsrp-Gi0/0/1-44" (default)
    VIPAddress = ""
    GroupID = ""
    PeerAddress = ""
    isActive = False
    ri = None
    hsrpSummary = Session.ExecCommand("show standby")
    for thisLine in hsrpSummary.splitlines():
      try:
        indentLevel = len(thisLine) - len(thisLine.lstrip(' '))
        if indentLevel == 0:
          # interface definition is changing
          if GroupID  and VIPAddress :
            neighborRegistry.RegisterNHRPPeer(self, instance, ri, L3Discovery.NHRPProtocol.HSRP, isActive, VIPAddress, GroupID, PeerAddress)
            VIPAddress = ""
            GroupID = ""
            PeerAddress = ""
            ri = None
          # -- 
          words = filter(None, thisLine.split(" "))
          if len(words) >= 3 :
            ifName = words[0]
            ri = self.GetInterfaceByName(ifName, instance)
            match = re.findall(r"(?<=Group )\d{0,99}", thisLine, re.IGNORECASE)
            if len(match) == 1 :  GroupID = words[2]
          continue
        if ri :
          l = thisLine.lower().lstrip()
          if l.startswith("virtual ip address is") :
            match = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", l, re.IGNORECASE)
            if len(match) == 1 : VIPAddress = match[0]
            continue
          if l.startswith("active router is local") :
            isActive = True
            continue
          if l.startswith("standby router is") :
            match = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", l, re.IGNORECASE)
            if len(match) == 1 : PeerAddress = match[0]
            continue
      except Exception as Ex:
        message = "JunOS Router Module Error : could not parse NHRP information <{0}> because : {1} ".format(thisLine, str(Ex))
        DebugEx.WriteLine(message)
        
    # -- register the last one
    if ri and VIPAddress and GroupID :
      neighborRegistry.RegisterNHRPPeer(self, instance, ri, L3Discovery.NHRPProtocol.HSRP, isActive, VIPAddress, GroupID, PeerAddress)    
    
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
      # Add the default (global) instance
      defInstance = L3Discovery.RoutingInstance()
      defInstance.LogicalSystemName = logicalSystemName
      defInstance.DeviceVendor = "Cisco"
      defInstance.Name = self._defaultRoutingInstanceName
      instances.append(defInstance)
      # construct CLI command
      cmd = "show vrf"
      # execute command and parse result
      vrf_lines = Session.ExecCommand(cmd).splitlines()
      # first line is column header
      headerLine = vrf_lines.pop(0)
      # expected headers are : Name, Default RD, Protocols, Interfaces
      for thisLine in vrf_lines: 
        vrfName = GetColumnValue(thisLine, headerLine, "Name", "  ")
        if vrfName :
          rd = GetColumnValue(thisLine, headerLine, "Default RD", "  ")
          thisInstance = L3Discovery.RoutingInstance()
          thisInstance.DeviceVendor = "Cisco"
          thisInstance.LogicalSystemName = "Default"
          thisInstance.Name = vrfName
          thisInstance.RD = rd
          instances.append(thisInstance)
      self._routingInstances[logicalSystemName] = instances
    
    result = self._routingInstances[logicalSystemName]
    return result
    
  def RouteTableSize(self, instance):
    """Returns the size of the route table for the requested routing instance"""
    instanceName = self._defaultRoutingInstanceName
    if instance : instanceName = instance.Name
    routeTableSize = -1
    try :
      cmd = "show ip route summary"
      if instanceName != self._defaultRoutingInstanceName:
        cmd = "show ip route vrf {0} summary".format(instanceName)   
            
      routeSummary = Session.ExecCommand(cmd)   
      routeTotals = filter(lambda s: s.startswith("Total"), routeSummary.splitlines())
      
      if len(routeTotals) > 0:
        # return the last number in Total line
        words = filter(None, routeTotals[0].split(' '))
        routeTableSize = int(words[2])
    except Exception as Ex :
      DebugEx.WriteLine("CiscoIOSRouter : error calculating route table size : {0}".format(str(Ex)))
    
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
        if instance.IsDefaultRoutingInstance() :
          cmd = "show ip route 0.0.0.0"
        else :
          cmd = "show ip route vrf {0} 0.0.0.0".format(instanceName)
      else:
        # query inet.0 route table for the requested instance
        if instance.IsDefaultRoutingInstance() :
          cmd = "show ip route"
        else:
          cmd = "show ip route vrf {0}".format(instanceName)
      routes = Session.ExecCommand(cmd)
      v = self.GetVersion()
      if "ios-xe software" in v.lower():
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
            # lets check if we find an ipAddress/MaskLength combination in the line
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
              # we expect only one ip addresses in these lines which is the prefix
              m = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b\/\d{1,2}", rLine)
              if len(m) == 1 :
                s = m[0]
                prefixAndMask = filter(None, s.split('/'))
                prefix = prefixAndMask[0]
                maskLength = int(prefixAndMask[1])
                expectingNextHop = True
                # this line should also contain the out interface as the last word
                words = filter(None, rLine.split(','))
                outInterface = words[-1]
                expectingNextHop = False
                parserSuccess = True
            else:
              if not expectingNextHop:
                # we expect two ip addresses in these lines, first is the prefix and second is next-hop check for the prefix first 
                m = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b\/\d{1,2}", rLine)
                if len(m) == 1 :
                  s = m[0]
                  prefixAndMask = filter(None, s.split('/'))
                  prefix = prefixAndMask[0]
                  maskLength = int(prefixAndMask[1])
                  expectingNextHop = True
                else:
                  # check if we find an ip address in line and if it was a subnet of last prefix
                  # unfortunately logic seems to be broken in cas of some IOS-XE, like below route table entry is totally crap :
                  #     159.63.0.0 / 27 is subnetted, 2 subnets
                  # S        159.63.248.32[1 / 0] via 212.162.30.89
                  # S        159.63.248.96[1 / 0] via 212.162.30.89               
                  m = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", rLine)
                  # Due to above issue , below check does not work and we need to trust the subnettedPrefix value anyhow
                  # if (m.Success && IPOperations.IsIPAddressInNetwork(m.Value, subnettedPrefix, subnettedMaskLength))    
                  if len(m) == 1:
                    # the maskLength is still valid for this prefix
                    prefix = m[0]
                    maskLength = subnettedMaskLength
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
                    outInterface = words[-1]
                    # discard outInterface if not a real interface name, like matches date pattern
                    m =  re.findall(r"(\d{1,2}w\d{1,2}d)|(\d{1,2}d\d{1,2}h)", outInterface)
                    if len(m) == 1:
                      outInterface = "";
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
              msg = "CiscoIOSRouter.RoutingTable() : error processing route table : {0}".format(str(Ex))
              DebugEx.WriteLine(msg)
            
      else:
        # Not an ios-xe
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
          words = filter(None, rLine.split(' '))
          # lets check if we find an ipAddress/MaskLength combination in the line
          prefixFound = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b\/\d{1,2}", rLine)
          # or just an ipAddress
          addressFound = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", rLine)
          # if the line contains the expression "subnetted" then we will learn the subnet mask for upcoming route entries and continue the loop
          if "subnetted" in rLine and len(prefixFound) == 1 :
            addressAndMask = prefixFound[0].split('/')
            if len(addressAndMask) == 2:
              try:
                maskLength = int(addressAndMask[1])
              except:
                pass
            # proceed to next rLine
            continue
          if len(prefixFound) == 1:
            addressAndMask = prefixFound[0].split('/')
            if len(addressAndMask) == 2:
              prefix = addressAndMask[0]
              try:
                maskLength = int(addressAndMask[1])
              except:
                pass
          elif len(addressFound) == 1:
            prefix = addressFound[0]
          else: 
            continue
            
          if prefix:
            parserSuccess = True
            if prefix == "0.0.0.0" : 
              maskLength = 0
            # get next-hop
            nexthopFound = re.findall(r"(?<=via )\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", rLine)
            if len(nexthopFound) == 1:
              nextHop = nexthopFound[0]
            # get preference
            routeDetails = re.findall(r"\[(.*?)\]", rLine)
            if len(routeDetails) == 1:
              preferences = routeDetails[0].split('/')
              adminDistance = preferences[0].strip('[')
              routeMetric = preferences[1].strip(']')
            # this line should also contain the out interface
            outInterface = words[-1]
          else:
            # no ip address in this line, proceed to next
            continue
          # here we already know a mask length and the actual routed prefix, so check the protocol  
          if rLine.startswith("B") :
            thisProtocol = NeighborProtocol.BGP
          elif rLine.startswith("O") or rLine.startswith("IA") or rLine.startswith("N1") or rLine.startswith("N2") or rLine.startswith("E1") or rLine.startswith("E2") :
            thisProtocol = NeighborProtocol.OSPF
          elif rLine.startswith("D") or rLine.startswith("EX") :
            thisProtocol = NeighborProtocol.EIGRP;
          elif rLine.startswith("R") :
            thisProtocol = NeighborProtocol.RIP
          elif rLine.startswith("L") :
            thisProtocol = NeighborProtocol.LOCAL
          elif rLine.startswith("C") :
            thisProtocol = NeighborProtocol.CONNECTED
          elif rLine.startswith("S") :
            thisProtocol = NeighborProtocol.STATIC
          else :
            thisProtocol = NeighborProtocol.UNKNOWN
          
          if thisProtocol != NeighborProtocol.UNKNOWN:
            if parserSuccess:
              try :
                rte = RouteTableEntry()
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
                msg = "CiscoIOSRouter.RoutingTable() : error processing route table : {0}".format(str(Ex))
                DebugEx.WriteLine(msg)
          
            
    except Exception as Ex:
      msg = "CiscoIOSRouter.RoutingTable() :unexpected error while processing route table : {0}".format(str(Ex))
      DebugEx.WriteLine(msg)
      raise Exception(msg)
    
    return parsedRoutes
      
class RouterIDCalculator():
  """Performs Router ID and AS Number calculations """
  def __init__(self, router):
    # self.Router will hold a reference to the parent CiscoIOSRouter instance
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
    l3interfaces = Session.ExecCommand("sh ip interface brief")
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
        DebugEx.WriteLine("CiscoIOSRouter.CalculateRouterIDAndASNumber() : error while parsing interface information : " + str(Ex))
    
   
    # get the running routing protocols for this routing instance
    runnintRoutingProtocols = self.Router.ActiveProtocols(instance)
    for thisProtocol in runnintRoutingProtocols:  
      if thisProtocol == L3Discovery.NeighborProtocol.BGP:
        # construct CLI command
        if instanceName == self.Router._defaultRoutingInstanceName :
          cmd = "show ip bgp summary"
        else:
          cmd = "show ip bgp vpnv4 vrf {0} summary".format(instanceName)
        
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
        cmd = "show ip ospf | i ID"
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
        cmd = "show ip eigrp topology | i ID"
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
        
      else :
        self.RouterID[instanceName][str(thisProtocol)] = globalRouterID   
          
  def Reset(self):
    self.RouterID = {}
    self.BGPASNumber = {}
    
class InterfaceParser(): 
  """Manage Cisco interfaces"""
  def __init__(self, router):
    #  self.Router will hold a reference to the parent CiscoIOSRouter instance
    self.Router = router
    # These are the list of interfaces collected by ParseInterfaces() method. 
    # A dictionary, keyed by routing instance name and containing Lists
    self.Interfaces = {}
    # Interface config cache. 
    # A dictionary keyed by Interface Name and containing strings
    self._interfaceConfigurations = {}
    # The running configuration of router
    self._running_config = None
    
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
    interfaces = Session.ExecCommand("show ip interface").splitlines()
    # Parse the result and fill up self.Interfaces list
    ri = L3Discovery.RouterInterface()
    lineCount = len(interfaces)
    currentLineIndex = 1
    for line in interfaces:
      try:  
        indentLevel = len(line) - len(line.lstrip(' '))
        if indentLevel == 0 or currentLineIndex == lineCount :
          # this is either a new interface block, or the end of the interface list
          if ri and ri.Name :
            # Add actual interface if vrf name matches instanceName
            if not ri.VRFName and instanceName == self.Router._defaultRoutingInstanceName or ri.VRFName == instanceName:
              ri.Configuration = self.GetInterfaceConfiguration(ri.Name)
              if ri.Configuration.find("encapsulation dot1q") >= 0 : 
                ri.PortMode = L3Discovery.RouterInterfacePortMode.L3Subinterface
                subinterfaceDefinition = next((cline for cline in ri.Configuration.splitlines() if cline.startswith("encapsulation dot1q")), "")
                ri.VLANS = subinterfaceDefinition.split(' ')[-1]
              elif ri.Address : ri.PortMode = L3Discovery.RouterInterfacePortMode.Routed
              elif ri.Configuration.find("switchport mode trunk") >= 0 : 
                ri.PortMode = L3Discovery.RouterInterfacePortMode.Trunk
                # get allowed vlans
                cmd = "show interfaces {0} trunk".format(ri.Name)                
                cmdResult = Session.ExecCommand(cmd)
                #Port        Mode         Encapsulation  Status        Native vlan
                #Fa0/2       on           802.1q         trunking      1
                #
                #Port     Vlans allowed on trunk
                #Fa0/2    1-4,7,11,13-4094
                #
                #Port        Vlans allowed and active in management domain
                #Fa0/2       1
                #
                #Port        Vlans in spanning tree forwarding state and not pruned
                #Fa0/2       1                
                vlanBlock = False
                for vLine in cmdResult.splitlines():
                  if "Vlans allowed on trunk" in vLine:
                    vlanBlock = True
                    continue
                  if vlanBlock and vLine.strip() == "" :
                    break;
                  elif vlanBlock:
                    words = filter(None, vLine.split(' '))
                    if len(words) == 2:
                      vlanList = words[0]
                      ri.VLANS = re.sub(r",", "|", vlanList)
              elif ri.Configuration.find("switchport mode access") >= 0 : 
                ri.PortMode = L3Discovery.RouterInterfacePortMode.Access
                accessVlan = next((cline for cline in ri.Configuration.splitlines() if cline.startswith("switchport access vlan")), "")
                ri.VLANS = accessVlan.split(' ')[-1]
              else : ri.PortMode = L3Discovery.RouterInterfacePortMode.Unknown
              ri.Description = next((cline for cline in ri.Configuration.splitlines() if cline.startswith("description")), "")
              self.Interfaces[instanceName].Add(ri)  
            if currentLineIndex == lineCount :
              break
          # Create new interface    
          ri = L3Discovery.RouterInterface()
          words = filter(None, line.split(' '))  
          # words should look like : GigabitEthernet0/0/0,is,up,line,protocol,is,up 
          ri.LogicalSystemName = "Default"    
          ri.Name = words[0]
          status = [i.strip(',') for i in words if "up" in i.lower() or "down" in i.lower()]
          ri.Status = ",".join(status)
        else:
          # this line belongs to an iterface information block
          sline = line.strip().lower()
          if sline.startswith("internet address"):
            addressAndMask = GetIPAddressAndMaskFromLine(sline).split('/')
            ri.Address = addressAndMask[0]
            ri.MaskLength = addressAndMask[1]
          
          elif sline.startswith("vpn routing/forwarding"):  
            words = filter(None, line.split(' '))   
            ri.VRFName = words[-1].strip('"')
        
        # PortMode and VLANS will be processed later in a second pass
      except Exception as Ex:
        DebugEx.WriteLine("CiscoIOSRouter.InterfaceParser.ParseInterfaces() : error parsing text {0}. Error is {1}".format(line, str(Ex)))
      
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
    
  def GetInterfaceByName(self, ifName, instance):
    """Returns a RouterInterface object for the interface specified by its name"""        
    # Init interface dictionary for instance
    instanceName = self.Router._defaultRoutingInstanceName
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
      self._running_config = Session.ExecCommand("show running-config")
      if len(self._running_config) < 100 and "Command authorization failed" in self._running_config:
        # some systems may not allow running "show run" but still allow "show tech", let's give a try :-)
        tech_support_ipc = Session.ExecCommand("show tech-support ipc")
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
    currentIntfName = ""
    currentIntfConfig = []
    for thisLine in self._running_config.splitlines():
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
      except Exception as Ex:
        message = "CiscoIOSRouter.InterfaceParser.ParseInterfaceConfigurations() : could not parse an interface configuration for line <{0}>. Error is : {1} ".format(thisLine, str(Ex))
        DebugEx.WriteLine(message)   
           
  def IsInterrestingInterface(self, intfName):
    """ Determines if a given name is an interface name we want to parse"""
    return intfName.startswith("ge-") or intfName.startswith("xe-") or intfName.startswith("et-") or intfName.startswith("ae") or intfName.startswith("irb") or intfName.startswith("vlan") or intfName.startswith("lo")
      
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
  
def GetIPAddressAndMaskFromLine(line):
  """Extracts the first match of an IP address and mask from a line of text and returns it
     Expected format is aaa.bbb.ccc.ddd/xx"""
  address = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/\d{1,2}", line)
  if len(address) == 1 : 
    return address[0]
  else: 
    return "" 
   
################### Script entry point ###################
if ConnectionInfo.Command == "CreateInstance":
  ActionResult = CiscoIOSRouter()
  ScriptSuccess = True
    