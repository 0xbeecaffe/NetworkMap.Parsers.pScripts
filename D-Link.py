#########################################################################
#                                                                       #
#  This file is a Python parser module for PGT Network Map and is       #
#  written to parse the configuration on DLink switches.                #
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
# last changed : 2019.08.05
scriptVersion = "1.0"
class DLinkSwitch(L3Discovery.IRouter):
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
      self._inventory = Session.ExecCommand("show unit")
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
      inv = self.GetInventory()
      lineIndex = -1
      modelLineIndex = -1
      for line in inv.splitlines():
        lineIndex += 1
        m = re.findall(r"Unit\s+Model Descr\s+Model Name", line, re.IGNORECASE)
        if len(m) > 0 :
          modelLineIndex = lineIndex + 2
          continue
        if lineIndex == modelLineIndex:
          lineWords = filter(None, line.split("  "))
          self._ModelNumber = lineWords[-1]
          break
    return self._ModelNumber
    
  def GetOperationStatusLabel(self):
    """Returns a string describibg current activity"""
    return self._operationStatusLabel
    
  def GetPlatform(self):
    """Return a string	to describe device Platform"""
    return "D-Link"
    
  def GetSession(self):
    """Returns the actual Session object"""
    return Session
    
  def GetStackCount(self):
    """Returns the number of members in a switch stack"""
    if self._stackCount == 0 :
      stackedswitches = Session.ExecCommand("show stack")
      members = re.findall(r"^\d+\s+(Auto)\s+(?!NOT_EXIST).*", stackedswitches, re.IGNORECASE | re.MULTILINE)
      self._stackCount = len(members)
    return self._stackCount
    
  def GetSupportTag(self):
    """Returns a string describing capability of this instance"""
    global scriptVersion
    return "D-Link switch support module - Python Parser v{0}".format(scriptVersion)
    
  def GetSupportedEngineVersion(self):
    """Returns the regex pattern covering supported Discovery Engine versions"""
    global scriptVersion
    return r"^7\.5.*"    
    
  def GetSystemSerial(self):
    """Returns System serial numbers as a string, calculated from Inventory"""
    if not self._SystemSerial :
      foundSerials = []
      inv = self.GetInventory()
      lineIndex = -1
      serialLineIndex = -1
      for line in inv.splitlines():
        lineIndex += 1
        m = re.findall(r"Unit\s+Serial-Number\s+Status\s+Up Time", line, re.IGNORECASE)
        if len(m) > 0 :
          serialLineIndex = lineIndex + 2
          continue
        if lineIndex >= serialLineIndex:
          # We are in serial number block
          if len(line.strip()) == 0 :
            # This is the last, empty line in block
            break
          lineWords = filter(None, line.split("  "))
          if len(lineWords) == 4:
            foundSerials.append(lineWords[1])
            continue
      self._SystemSerial = ",".join(foundSerials)
    return self._SystemSerial
    
  def GetSystemMAC(self, instance):
    """Returns the MAC addresses associated with the local system for the given routing instance"""
    systemMAC = ""
    v = self.GetVersion()
    rep_SystemMAC = r"(?<=System MAC Address: )[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}"
    try:
      systemMAC = re.findall(rep_SystemMAC, v, re.IGNORECASE )[0]
    except Exception as Ex:
      DebugEx.WriteLine("DLinkSwitch.GetSystemMAC() : unexpected error : {0}".format(str(Ex)))
    return systemMAC    
    
  def GetDeviceType(self):
    """Returns Type string that can be Switch, Router or Firewall, depending on Model"""
    return "Switch"
    
  def GetVendor(self):
    """Must return a string matching the Vendor name this parser is responible for"""
    return "D-Link"
    
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
      rep_staticEntries = r"(?<=Total Entries:).*"
      m_totalEntries = re.findall(rep_staticEntries, response, re.IGNORECASE | re.MULTILINE)
      if len(m_totalEntries) > 0 : 
        totalEntries = m_totalEntries[0].strip()
        numEntries = 0
        if totalEntries.isdigit(): 
          numEntries = int(totalEntries)
        if numEntries > 0 :  
          self._runningRoutingProtocols[instance.Name].append(NeighborProtocol.STATIC)  
        
 
      # LLDP - only for default instance
      if instanceName == defaultInstanceName:
        response = Session.ExecCommand("sh lldp | i LLDP State")
        lldpEnabled = "Enabled" in response
        if lldpEnabled: 
          self._runningRoutingProtocols[instanceName].Add(NeighborProtocol.LLDP)
          
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
    v = Session.ExecCommand("show running-config | i D-link")
    result = "d-link" in v.lower()
    if not result : v = Session.ExecCommand("show running-config | i D-Link")
    result = "d-link" in v.lower()
    return result 
    
  def RegisterNHRP(self, neighborRegistry, instance):
    """Performs NHRP database registration"""
    # Not implemented
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
      # Add the default (global) instance
      defInstance = L3Discovery.RoutingInstance()
      defInstance.LogicalSystemName = logicalSystemName
      defInstance.DeviceVendor = "D-Link"
      defInstance.Name = self._defaultRoutingInstanceName
      instances.append(defInstance)
      # construct CLI command
      cmd = "show ip vrf"
      # execute command and parse result
      vrf_lines = Session.ExecCommand(cmd).splitlines()
      failwords = self.ScriptSettings.FailedCommandPattern.split(";")
      if not any(fw in vrf_lines for fw in failwords) and not ("invalid input" in vrf_lines.lower()):
        # first line is column header
        headerLine = vrf_lines.pop(0)
        # expected headers are : Name, Default RD, Protocols, Interfaces
        for thisLine in vrf_lines:
          try: 
            vrfName = GetColumnValue(thisLine, headerLine, "VRF Name", "  ")
            if "--" in vrfName : continue
            if vrfName :
              rd = GetColumnValue(thisLine, headerLine, "RD", "  ")
              thisInstance = L3Discovery.RoutingInstance()
              thisInstance.DeviceVendor = "D-Link"
              thisInstance.LogicalSystemName = "Default"
              thisInstance.Name = vrfName
              thisInstance.RD = rd
              instances.append(thisInstance)
          except Exception as Ex:
            DebugEx.WriteLine("DLinkSwitch : error while parsing vrf line \"{0}\". Error is : {1}".format(thisLine, str(Ex)))
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
        routeTableSize = int(words[1])
    except Exception as Ex :
      DebugEx.WriteLine("DLinkSwitch : error calculating route table size : {0}".format(str(Ex)))
    
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
              msg = "DLinkSwitch.RoutingTable() : error processing route table : {0}".format(str(Ex))
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
                msg = "DLinkSwitch.RoutingTable() : error processing route table : {0}".format(str(Ex))
                DebugEx.WriteLine(msg)
          
            
    except Exception as Ex:
      msg = "DLinkSwitch.RoutingTable() :unexpected error while processing route table : {0}".format(str(Ex))
      DebugEx.WriteLine(msg)
      raise Exception(msg)
    
    return parsedRoutes
      
class RouterIDCalculator():
  """Performs Router ID and AS Number calculations """
  def __init__(self, router):
    # self.Router will hold a reference to the parent DLinkSwitch instance
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
        DebugEx.WriteLine("DLinkSwitch.CalculateRouterIDAndASNumber() : error while parsing interface information : " + str(Ex))
    
   
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
      elif thisProtocol == L3Discovery.NeighborProtocol.LLDP:
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
  """Manage DLink switch interfaces"""
  def __init__(self, router):
    #  self.Router will hold a reference to the parent DLinkSwitch instance
    self.Router = router
    # These are the list of interfaces collected by ParseInterfaces() method. 
    # A dictionary, keyed by routing instance name and containing Lists
    self.Interfaces = {}
    # Interface config cache. 
    # A dictionary keyed by Interface Name and containing strings
    self._interfaceConfigurations = {}
    # The running configuration of router
    self._running_config = None
    # VLAN database containing VLAN instances
    self._vlans = []
    # VLAN database dictionary containing VLAN instances keyed by VLAN ID
    self._vlanNames = {}
    # VLAN database dictionary containing VLAN instances keyed by VLAN Name
    self._vlanIDs = {}
    
  def ParseInterfaces(self, instance) :
    """Collects interface details for all interfaces of specified routing instance, but do not collect interface configuration """
    # First parse the VLAN database if missing
    if len(self._vlanIDs) == 0 : self.ParseVLANDatabase()    
    # Get the interfaces configurations
    if len(self._interfaceConfigurations) == 0 : self.ParseInterfaceConfigurations()
    # Init interface dictionary for the requested instance
    instanceName = self.Router._defaultRoutingInstanceName
    if instance : instanceName = instance.Name
    if self.Interfaces.get(instanceName, None) == None:
      self.Interfaces[instanceName] = [] 
    # Query the device interfaces
    interfaces = Session.ExecCommand("show interfaces status").splitlines()
    # Parse the result and fill up self.Interfaces list
    lineCount = len(interfaces)
    currentLineIndex = 1
    for line in interfaces:
      try:  
        words = filter(None, line.split(' '))  
        # Remove (c) or (f) qualifier from interface name
        if len(words) > 0 : intfName = re.sub(r"\(([cC]|[fF])\)", "", words[0]).lower()
        else : continue
        # words should look like : eth1/0/1,connected,1,a-full,a-1000,1000BASE-T   
        if len(words) == 6 and self.IsInterrestingInterface(intfName) :
          ifConfig = self.GetInterfaceConfiguration(intfName) 
          intfVRFName = self.Router._defaultRoutingInstanceName
          rep_intfVRFName = r"(?<=ip vrf forwarding ).*"
          m_vrfName = re.findall(rep_intfVRFName, ifConfig, re.IGNORECASE | re.MULTILINE)
          if len(m_vrfName)  > 0 : intfVRFName = m_vrfName[0]
          if intfVRFName == instanceName:
            # Create new interface    
            ri = L3Discovery.RouterInterface()
            ri.VRFName = intfVRFName
            ri.LogicalSystemName = "Default"    
            ri.Name = intfName
            ri.Configuration = ifConfig
            intfStatus = words[1].strip()
            if intfStatus == "connected" : intfStatus = "up/up"
            elif intfStatus == "not-connected" : intfStatus = "down/up"
            elif intfStatus == "disabled" : intfStatus = "down/down"
            ri.Status = intfStatus
            ri.PortMode = L3Discovery.RouterInterfacePortMode.Access
            rep_intfAddress = r"(?<=ip address )(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"
            mi_intfAddress = re.finditer(rep_intfAddress, ifConfig, re.IGNORECASE | re.MULTILINE)
            for index, match in enumerate(mi_intfAddress):
              ri.Address = match.group(1)
              subnetMask = match.group(2)
              maskLength = str(IPOperations.GetMaskLength(subnetMask))
              ri.MaskLength = maskLength
              ri.PortMode = L3Discovery.RouterInterfacePortMode.Routed
              break
                         
            if "switchport mode trunk" in ifConfig : 
              ri.PortMode = L3Discovery.RouterInterfacePortMode.Trunk             
              taggedVLANs = [v for v in self._vlans if v.IsInterfaceTagged(ri.Name)]
              vlanList = map(lambda v : "{0}|{1}".format(v.VLAN_Name, v.VLAN_ID), taggedVLANs)
              ri.VLANS = ",".join(vlanList)
              
            elif "switchport mode access" in ifConfig : 
              ri.PortMode = L3Discovery.RouterInterfacePortMode.Access
              m_vlanID = re.findall(r"(?<=switchport access vlan )\d+", ifConfig, re.IGNORECASE)
              if len(m_vlanID) == 1:
                vlanID = m_vlanID[0]
                v = self._vlanNames.get(vlanID, "")
                if v :
                  ri.VLANS = "{0}|{1}".format(v.VLAN_Name, vlanID)
                else :
                  ri.VLANS = vlanID
              else :
                # assume default vlan 1
                v = self._vlanNames.get("1", "")
                if v :
                  ri.VLANS = "{0}|1".format(v.VLAN_Name)
                else :
                  ri.VLANS = "1"
            else : ri.PortMode = L3Discovery.RouterInterfacePortMode.Unknown
            m_description = re.findall(r"(?<=description ).*", ifConfig, re.IGNORECASE )
            if len(m_description) > 0 : 
              ri.Description = m_description[0]
            self.Interfaces[instanceName].Add(ri)  
          if currentLineIndex == lineCount :
            break
      except Exception as Ex:
        DebugEx.WriteLine("DLinkSwitch.InterfaceParser.ParseInterfaces() : error parsing text {0}. Error is {1}".format(line, str(Ex)))
        
    # Check for mgmt, vlan and loopback interfaces
    ipinterfaces = Session.ExecCommand("show ip interface brief")
    for line in ipinterfaces.splitlines():
      try:  
        words = filter(None, line.split(' '))  
        if len(words) == 3 : intfName = words[0].lower()
        else : continue        
        # words should look like : vlan1,10.0.44.253,up       
        if self.IsInterrestingInterface(intfName) :            
          ifConfig = self.GetInterfaceConfiguration(intfName)
          intfVRFName = self.Router._defaultRoutingInstanceName
          rep_intfVRFName = r"(?<=ip vrf forwarding ).*"
          m_vrfName = re.findall(rep_intfVRFName, ifConfig, re.IGNORECASE | re.MULTILINE)
          if len(m_vrfName)  > 0 : intfVRFName = m_vrfName[0]
          if intfVRFName == instanceName:              
            # Create new interface    
            ri = L3Discovery.RouterInterface()
            ri.VRFName = intfVRFName
            ri.LogicalSystemName = "Default"    
            ri.Name = intfName
            ri.Configuration = ifConfig        
            # consider admin status up for these interfaces
            ri.Status = "{0}/up".format(words[2])
            ri.PortMode = L3Discovery.RouterInterfacePortMode.Routed
            rep_intfAddress = r"(?<=ip address )(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"
            mi_intfAddress = re.finditer(rep_intfAddress, ifConfig, re.IGNORECASE | re.MULTILINE)
            for index, match in enumerate(mi_intfAddress):
              ri.Address = match.group(1)
              subnetMask = match.group(2)
              maskLength = str(IPOperations.GetMaskLength(subnetMask))
              ri.MaskLength = maskLength
              
            m_description = re.findall(r"(?<=description ).*", ifConfig, re.IGNORECASE )
            if len(m_description) > 0 : 
              ri.Description = m_description[0]
            self.Interfaces[instanceName].Add(ri) 
                  
      except Exception as Ex:
        DebugEx.WriteLine("DLinkSwitch.InterfaceParser.ParseInterfaces() : error parsing text {0}. Error is {1}".format(line, str(Ex)))
      
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
    foundInterface = next((intf for intf in self.Interfaces[instanceName] if intf.Name.lower().strip() == ifName.lower().strip()), None)
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
    if not ifName : return None
    # D-Link is handling management ionterface naming in an idiot way
    if ifName == "mgmt_ipif" : ifName = "Mgmt0"
    ifConfig = self._interfaceConfigurations.get(ifName.lower(), "")
    return ifConfig 
    
  def ParseInterfaceConfigurations(self):
    """Gets router running configurtion to collect interface configurations""" 
    # Get running configuration to parse
    if not self._running_config:
      self._running_config = Session.ExecCommand("show running-config")
          
    self._interfaceConfigurations = {}
    currentIntfName = ""
    currentIntfConfig = []
    re_intfNameLine = re.compile(r"(?<=interface ).*", re.IGNORECASE)
    for thisLine in self._running_config.splitlines():
      try:
        intfName = re_intfNameLine.findall(thisLine)
        if len(intfName) == 1 :
          # This should be a new interface definition
          if currentIntfName != "":
            # add previous interface
            self._interfaceConfigurations[currentIntfName.lower()] = "\r\n".join(currentIntfConfig)
          # Clear current configuration
          currentIntfConfig = []
          currentIntfName = self.InterfaceNameToShort(intfName[0])
        else:
          sline = thisLine.strip(' ')
          if sline != "!" :
           currentIntfConfig.append(sline)
      except Exception as Ex:
        message = "DLinkSwitch.InterfaceParser.ParseInterfaceConfigurations() : could not parse an interface configuration for line <{0}>. Error is : {1} ".format(thisLine, str(Ex))
        DebugEx.WriteLine(message)   
  
  def ParseVLANDatabase(self):
    """Populates vlanNames and vlanIDs dictionaries by parsing switch vlan database"""
    self._vlanIDs = {}
    self._vlanNames = {}
    # match => VLAN Name
    rep_VLANName = r"(?<=Name : ).*"
    # regex group 1 : member ports
    rep_TaggedMemberPorts = r"(?<=(?:\s|\n)Tagged Member Ports)(?:\s+:)(.*)"
    # regex group 1 : member ports
    rep_UntggedMemberPorts = r"(?<=Untagged Member Ports)(?:\s+:)(.*)"
    # Split command output to VLAN blocks. WARNING : splitting does not work with line engins \r\n, only if \r removed !
    rep_VLANBlocks = r"VLAN\s(\d+).*((?:(?!^\sVLAN\s\d+)[\s\S])*)"
    vlanData = Session.ExecCommand("show vlan") 
    vlanData = re.sub(r"\r", "", vlanData)
    ri_vlanBlocks = re.finditer(rep_VLANBlocks, vlanData, re.MULTILINE)
    for vbIndex, vbMatch in enumerate(ri_vlanBlocks): 
      try:
        vlanID = vbMatch.group(1)
        thisVlanBlock = vbMatch.group(2)
        m_vlanName = re.findall(rep_VLANName, thisVlanBlock, re.IGNORECASE)
        if len(m_vlanName) > 0 :
          vlanName = m_vlanName[0]
          thisVLAN = VLAN(vlanName, vlanID)
          mi_taggedPorts = re.finditer(rep_TaggedMemberPorts, thisVlanBlock, re.IGNORECASE | re.MULTILINE)
          for index, tmatch in enumerate(mi_taggedPorts):
            tmembers = tmatch.group(1).strip().split(",")
            thisVLAN.TaggedInterfaces = filter(None, tmembers)
          mi_untaggedPorts = re.finditer(rep_UntggedMemberPorts, thisVlanBlock, re.IGNORECASE | re.MULTILINE)
          for index, umatch in enumerate(mi_untaggedPorts):
            umembers = umatch.group(1).strip().split(",")
            thisVLAN.UntaggedInterfaces = filter(None, umembers)
          self._vlans.append(thisVLAN)
          self._vlanIDs[vlanName] = thisVLAN
          self._vlanNames[vlanID] = thisVLAN
      except Exception as Ex:
        message = "Hirschmann.InterfaceParser.ParseInterfaceConfigurations() : could not parse a vlan data. Error is : {0} ".format(str(Ex))
           
  def IsInterrestingInterface(self, intfName):
    """ Determines if a given name is an interface name we want to parse"""
    return intfName.startswith("eth") or intfName.startswith("vlan") or intfName.startswith("lo") or intfName.startswith("port-channel") or intfName.startswith("mgmt")
      
  def Reset(self) :
    self.Interfaces = {}
    self._interfaceConfigurations = {}
    self._running_config = None
    self._vlan = []
    self._vlanIDs = {}
    self._vlanNames = {}
    
  def InterfaceNameToShort(self, longName):
    """Converts a long DLink interface name to its short representation"""
    inputName = longName.lower().strip()
    shortName = None
    if inputName.startswith("ethernet ") : 
      shortName = inputName.replace("ethernet ", "eth")
    if inputName.startswith("port-channel ") : 
      shortName = inputName.replace("port-channel ", "po")      
    if shortName : return shortName 
    else : return longName
    
  def InterfaceNameToLong(self, shortName):
    """Converts a short DLink interface name to its long representation"""
    inputName = shortName.lower().strip()
    longName = None
    if inputName.startswith("eth") and not "ethernet" in inputName : 
      longName = inputName.replace("eth", "ethernet ")
    if inputName.startswith("po") and not "port-channel " in inputName : 
      longName = inputName.replace("po", "port-channel ")      
    if longName : return longName
    else : return shortName
    
    
class VLAN():
  def __init__(self, name, id):
    self.VLAN_ID = id
    self.VLAN_Name = name
    # List of interfaces names and interface ranges where the VLAN is tagged
    self.TaggedInterfaces = []
    # List of interfaces names and interface ranges where the VLAN is untagged
    self.UntaggedInterfaces = []
  def _IsInerfaceInRange(self, interfaceName, interfaceMemberList):
    """Determines if the specified interface belongs to the given interface member list that may contain ranges"""
    if interfaceName in interfaceMemberList : return true
    # Now comes the more difficult part, check interfaces ranges
    intfIDs = re.findall(r"\d+", interfaceName)
    if len(intfIDs) != 3 : return false
    intfModule = int(intfIDs[0])
    intfSlot = int(intfIDs[1])
    intfPort = int(intfIDs[2])
    intfRanges = [t for t in interfaceMemberList if "-" in t]
    intfInAnyRange = False
    for thisRange in intfRanges:
      r = thisRange.split("-")
      if len(r) != 2: break
      # --
      startMember = r[0]
      startIDs = re.findall(r"\d+", startMember)
      if len(startIDs) != 3 : break
      startModule = int(startIDs[0])
      startSlot = int(startIDs[1])
      startPort = int(startIDs[2])
      # --
      endMember = r[1]
      endIDs = re.findall(r"\d+", endMember)
      if len(endIDs) != 3 : break
      endModule = int(endIDs[0])
      endSlot = int(endIDs[1])
      endPort = int(endIDs[2])
      intfInAnyRange = intfModule >= startModule and intfModule <= endModule and intfSlot >= startSlot and intfSlot <= endSlot and intfPort >= startPort and intfPort <= endPort
      if intfInAnyRange : break
      
    return intfInAnyRange
  
  def IsInterfaceTagged(self, interfaceName):
    """Determines if current VLAN is allowed and tagged on the specified interface name. Use short interface names to query"""
    return self._IsInerfaceInRange(interfaceName, self.TaggedInterfaces)
  
  def IsInterfaceUntagged(self, interfaceName):
    """Determines if current VLAN is allowed and tagged on the specified interface name. Use short interface names to query"""
    return self._IsInerfaceInRange(interfaceName, self.UntaggedInterfaces)    
    
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
  ActionResult = DLinkSwitch()
  ScriptSuccess = True
    