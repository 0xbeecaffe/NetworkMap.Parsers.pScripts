#########################################################################
#                                                                       #
#  This file is a Python parser module for PGT Network Map and is       #
#  written to parse basic device information on D-Link                  #
#  DGS 3100/3400/3600 series switches                                   # 
#                                                                       #
#  You may not use this file without a valid PGT Enterprise license.    #
#  You may not duplicate or create derivative work from this script     #
#  without a valid PGT Enterprise license                               #
#                                                                       #
#  Copyright Laszlo Frank (c) 2020                                      #
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
from itertools import islice
# last changed : 2020.02.05
scriptVersion = "3.0"
class DLinkSwitch(L3Discovery.IRouter):
  # Beyond _maxRouteTableEntries only the default route will be queried
  _maxRouteTableEntries = 30000    
  _defaultRoutingInstanceName = ""
  def __init__(self):
    # The Dlink switch type
    self._switchType = DLinkSwitchType.Unknown
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
      if self._switchType == DLinkSwitchType.DGS3600 :
        self._inventory = Session.ExecCommand("show unit")
      elif self._switchType == DLinkSwitchType.DGS3100 or self._switchType == DLinkSwitchType.DGS3400 :
        self._inventory = Session.ExecCommand("show switch")
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
      if self._switchType == DLinkSwitchType.DGS3600:
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
      elif self._switchType == DLinkSwitchType.DGS3100 or self._switchType == DLinkSwitchType.DGS3400:
        rep_deviceType = r"Device Type\s+:\s(.*)"
        try:       
           self._ModelNumber = GetRegexGroupMatches(rep_deviceType, inv, 1)[0]
        except:
          self._ModelNumber = "Unknown"
        
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
      if self._switchType == DLinkSwitchType.DGS3600:
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
      elif self._switchType == DLinkSwitchType.DGS3100 or self._switchType == DLinkSwitchType.DGS3400:
        rep_serialNumber = r"Serial Number\s+:\s([^(]*)"
        try:       
           foundSerials.append(GetRegexGroupMatches(rep_serialNumber, inv, 1)[0])
        except Exception as Ex:
          DebugEx.WriteLine("DLinkSwitch.GetSystemSerial() : unexpected error : {0}".format(str(Ex)))
      self._SystemSerial = ",".join(foundSerials)
    
    return self._SystemSerial
    
  def GetSystemMAC(self, instance):
    """Returns the MAC addresses associated with the local system for the given routing instance"""
    systemMAC = ""
    if self._switchType == DLinkSwitchType.DGS3600:
      v = self.GetVersion()
      rep_SystemMAC = r"(?<=System MAC Address: )[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}-[a-f0-9]{2}"
      try:
        systemMAC = re.findall(rep_SystemMAC, v, re.IGNORECASE )[0]
      except Exception as Ex:
        DebugEx.WriteLine("DLinkSwitch.GetSystemMAC() : unexpected error : {0}".format(str(Ex)))
        
    elif self._switchType == DLinkSwitchType.DGS3100 or self._switchType == DLinkSwitchType.DGS3400:
      inv = self.GetInventory()
      rep_SystemMAC = r"MAC Address\s+:\s(.*)"
      try:
        systemMAC = GetRegexGroupMatches(rep_SystemMAC, inv, 1 )[0]
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
      if self._switchType == DLinkSwitchType.DGS3600:
        self._versionInfo = Session.ExecCommand("show version")
      elif self._switchType == DLinkSwitchType.DGS3100 or self._switchType == DLinkSwitchType.DGS3400:
        self._versionInfo = Session.ExecCommand("show switch")
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
      if self._switchType == DLinkSwitchType.DGS3600:
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
      elif self._switchType == DLinkSwitchType.DGS3100 or self._switchType == DLinkSwitchType.DGS3400:      
        # For DGS3100 series only support LLDP if enabled
        if instanceName == defaultInstanceName:
          response = Session.ExecCommand("sh lldp")
          r_lldpStatus = re.findall(r"LLDP Status\s+:\sEnabled", response, re.IGNORECASE | re.MULTILINE)
          lldpEnabled = len(r_lldpStatus) == 1
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
    try:
      # "show switch" is understood by all platforms, while "show version" is not
      v = Session.ExecCommand("show switch")
      r = re.findall(r"DGS-31\d{2}", v, re.IGNORECASE)
      if len(r) == 1:
        self._switchType = DLinkSwitchType.DGS3100
      else:
        r = re.findall(r"DGS-34\d{2}", v, re.IGNORECASE)
        if len(r) == 1:
          self._switchType = DLinkSwitchType.DGS3400
    except Exception as Ex:
      pass
    
    if self._switchType == DLinkSwitchType.Unknown:
      try:
        v = Session.ExecCommand("show version")
        r = re.findall(r"DGS-36\d{2}", v, re.IGNORECASE)
        if len(r) == 1:
          self._switchType = DLinkSwitchType.DGS3600
          # Turn off terminal paging for this model
          Session.SendText("term len 0")
      except Exception as Ex:
        pass
      
    return self._switchType != DLinkSwitchType.Unknown
    
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
    self._switchType = DLinkSwitchType.Unknown
    
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
      if self._switchType == DLinkSwitchType.DGS3600:
        # construct CLI command
        cmd = "show ip vrf"
        # execute command and parse result
        vrfs = Session.ExecCommand(cmd)
        vrf_lines = vrfs.splitlines()
        failwords = self.ScriptSettings.FailedCommandPattern.split(";")
        if not any(fw in vrfs for fw in failwords) and not ("invalid input" in vrfs.lower()):
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
      elif self._switchType == DLinkSwitchType.DGS3100 or self._switchType == DLinkSwitchType.DGS3400:
        # on DGS3100/3400 only the default routing ionstance is supported
        self._routingInstances[logicalSystemName] = instances    
    result = self._routingInstances[logicalSystemName]
    return result
    
  def RouteTableSize(self, instance):
    """Returns the size of the route table for the requested routing instance"""
    instanceName = self._defaultRoutingInstanceName
    if instance : instanceName = instance.Name
    routeTableSize = -1
    try :
      if self._switchType == DLinkSwitchType.DGS3600:
        cmd = "show ip route summary"
        if instanceName != self._defaultRoutingInstanceName:
          cmd = "show ip route vrf {0} summary".format(instanceName)   
              
        routeSummary = Session.ExecCommand(cmd)   
        routeTotals = filter(lambda s: s.startswith("Total"), routeSummary.splitlines())
        
        if len(routeTotals) > 0:
          # return the last number in Total line
          words = filter(None, routeTotals[0].split(' '))
          routeTableSize = int(words[1])
      elif self._switchType == DLinkSwitchType.DGS3100 or self._switchType == DLinkSwitchType.DGS3400:
        cmd = "show iproute"
        response = Session.ExecCommand(cmd)  
        rep_TotalEntries = r"^Total Entries\s+:\s+(\d)" 
        routeTableSize =int(GetRegexGroupMatches(rep_TotalEntries, response, 1)[0])
        
    except Exception as Ex :
      DebugEx.WriteLine("DLinkSwitch : error calculating route table size : {0}".format(str(Ex)))
    
    return routeTableSize
      
  def RoutingTable(self, instance):
    """Returns the list of RouteTableEntry objects for requested RoutingInstance. TODO : Not implemented"""
    parsedRoutes = []
    try:
      if instance : 
        instanceName = instance.Name
      if self._switchType == DLinkSwitchType.DGS3600:
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
      elif self._switchType == DLinkSwitchType.DGS3100 or self._switchType == DLinkSwitchType.DGS3400:
        routes = Session.ExecCommand("show iproute") 
        pass
           
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
    if self.Router._switchType == DLinkSwitchType.DGS3600:   
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
    elif self.Router._switchType == DLinkSwitchType.DGS3100 or self.Router._switchType == DLinkSwitchType.DGS3400:
      # BGP is not supported on this type of switch
      self.BGPASNumber[instanceName] = ""
      rep_ipaddress = r"^IP Address\s+:\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
      ipif = Session.ExecCommand("show ipif")
      m_addresses = GetRegexGroupMatches(rep_ipaddress, ipif, 1)
      if len(m_addresses) > 0:
        try :
          # find the interface with highest ip address
          highestIPLine = (sorted(m_addresses, key=lambda addr: IP2Int(addr))[-1]).strip()
          if highestIPLine:
            globalRouterID = highestIPLine
        except Exception as Ex :
          DebugEx.WriteLine("DLinkSwitch.CalculateRouterIDAndASNumber() : error while parsing interface information : " + str(Ex))   
      
      # get the running routing protocols for this routing instance
      runnintRoutingProtocols = self.Router.ActiveProtocols(instance)
      for thisProtocol in runnintRoutingProtocols:
        if thisProtocol == L3Discovery.NeighborProtocol.LLDP:
          # only for default (global) routing instance
          if instanceName == self.Router._defaultRoutingInstanceName :
            self.RouterID[instanceName][str(thisProtocol)] = self.Router.GetHostName()   
        else:
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
      
    if self.Router._switchType == DLinkSwitchType.DGS3600: 
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
    
    elif self.Router._switchType == DLinkSwitchType.DGS3100:
      # Query the ports
      interfaces = Session.ExecCommand("show ports").splitlines()
      # Be careful, tis idiot switch reports "Port" in first header line for both column 0 and 1
      headerLine = interfaces[0]
      # filter the interface lines for lines starting with valid a port name
      portLines = filter(lambda x: re.match(r"^\d+:\d+\s+", x, re.IGNORECASE), interfaces)
      # Parse the result and fill up self.Interfaces list
      for thisLine in portLines:
        try:  
          # getting column value for simply "Port" should return the first value in column 0
          portName = GetColumnValue(thisLine, headerLine, "Port", " ")
          portConfig = self.GetInterfaceConfiguration(portName) 
          # getting column value for sthe second occurence of "Port" should return value in column 1
          portAdminStatus = GetColumnValue(thisLine, headerLine, "Port", " ", 2).lower()
          portLinkStatus = GetColumnValue(thisLine, headerLine, "Connection", " ").lower()
          portStatus = "unknown"
          if portAdminStatus == "enabled" : 
            if portLinkStatus == "link down" : portStatus = "up/down"
            else : portStatus = "up/up"
          else:
            if portLinkStatus == "link down" : portStatus = "down/down"
            else : portStatus = "down/up"
 
          # Create new interface    
          ri = L3Discovery.RouterInterface()
          ri.Name = portName
          ri.Status = portStatus
          ri.Configuration = portConfig
          ri.VRFName = self.Router._defaultRoutingInstanceName
          ri.LogicalSystemName = "Default" 
          # Default to access mode          
          ri.PortMode = L3Discovery.RouterInterfacePortMode.Access
          # Get the VLANs this port is member of
          taggedVLANs = [v for v in self._vlans if v.IsInterfaceTagged(ri.Name)]
          if len(taggedVLANs) > 1 :
            # More than one VLANs are assigned, assume trunk mode    
            ri.PortMode = L3Discovery.RouterInterfacePortMode.Trunk
          # Generate VLAN list name
          vlanList = map(lambda v : "{0}|{1}".format(v.VLAN_Name, v.VLAN_ID), taggedVLANs)
          ri.VLANS = ",".join(vlanList)                       
          self.Interfaces[instanceName].Add(ri)  
        except Exception as Ex:
          DebugEx.WriteLine("DLinkSwitch.InterfaceParser.ParseInterfaces() : error parsing text {0}. Error is {1}".format(thisLine, str(Ex)))
    
    elif self.Router._switchType == DLinkSwitchType.DGS3400:
      # Query the ports
      interfaces = Session.ExecCommand("show ports").splitlines()
      # We cannot use column header for alignment in tis idiot switch output format but ,ust rely on line splitting
      # Filter the interface lines for lines starting with valid a port name
      portLines = filter(lambda x: re.match(r"^\s?\d+\s+", x, re.IGNORECASE), interfaces)
      # Parse the result and fill up self.Interfaces list
      for thisLine in portLines:
        try:  
          words = filter(None, thisLine.split("  "))
          # words should look like :  1,Enabled,Auto/Disabled,Link Down,Enabled   
          if len(words) != 5 : 
            continue
          portName = words[0].strip()
          portConfig = self.GetInterfaceConfiguration(portName) 
          portAdminStatus = words[1].strip().lower()
          portLinkStatus = words[3].strip().lower()
          portStatus = "unknown"
          if portAdminStatus == "enabled" : 
            if portLinkStatus == "link down" : portStatus = "up/down"
            else : portStatus = "up/up"
          else:
            if portLinkStatus == "link down" : portStatus = "down/down"
            else : portStatus = "down/up"
 
          # Create new interface    
          ri = L3Discovery.RouterInterface()
          ri.Name = portName
          ri.Status = portStatus
          ri.Configuration = portConfig
          ri.VRFName = self.Router._defaultRoutingInstanceName
          ri.LogicalSystemName = "Default" 
          # Default to access mode          
          ri.PortMode = L3Discovery.RouterInterfacePortMode.Access
          # Get the VLANs this port is member of
          taggedVLANs = [v for v in self._vlans if v.IsInterfaceTagged(ri.Name)]
          if len(taggedVLANs) > 1 :
            # More than one VLANs are assigned, assume trunk mode    
            ri.PortMode = L3Discovery.RouterInterfacePortMode.Trunk
          # Generate VLAN list name
          vlanList = map(lambda v : "{0}|{1}".format(v.VLAN_Name, v.VLAN_ID), taggedVLANs)
          ri.VLANS = ",".join(vlanList)                       
          self.Interfaces[instanceName].Add(ri)  
        except Exception as Ex:
          DebugEx.WriteLine("DLinkSwitch.InterfaceParser.ParseInterfaces() : error parsing text {0}. Error is {1}".format(thisLine, str(Ex)))          
                  
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
    if self.Router._switchType == DLinkSwitchType.DGS3600:
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
    elif self.Router._switchType == DLinkSwitchType.DGS3100 or self.Router._switchType == DLinkSwitchType.DGS3400:
      if not self._running_config:
        self._running_config = Session.ExecCommand("show configuration running")
      # No concept of full port config in this stupid switch
      self._interfaceConfigurations = {}
      currentIntfName = ""
      currentIntfConfig = []      
  
  def ParseVLANDatabase(self):
    """Populates vlanNames and vlanIDs dictionaries by parsing switch vlan database"""
    self._vlanIDs = {}
    self._vlanNames = {}
    if self.Router._switchType == DLinkSwitchType.DGS3600:
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
          message = "DLink.InterfaceParser.ParseVLANDatabase() : could not parse a vlan data. Error is : {0} ".format(str(Ex))
          
    elif self.Router._switchType == DLinkSwitchType.DGS3100 or self.Router._switchType == DLinkSwitchType.DGS3400:
      # match => VLAN ID in regex group 1
      rep_VLANID = r"VID\s+:\s+(\d+)"    
      # match => VLAN Name in regex group 1
      rep_VLANName = r"VLAN Name\s+:\s+(.*)"
      # regex group 1 : member ports
      rep_TaggedMemberPorts = r"(?<=(?:\s|\n)Member Ports)(?:\s+:)(.*)"
      # regex group 1 : member ports
      rep_UntggedMemberPorts = r"(?<=Untagged Ports)(?:\s+:)(.*)"
      # Split command output to VLAN blocks. WARNING : splitting does not work with line engins \r\n, only if \r removed !
      rep_VLANBlocks = r"VID.*\s*((?:(?!^VID)[\s\S])*)"
      vlanData = Session.ExecCommand("show vlan") 
      vlanData = re.sub(r"\r", "", vlanData)
      ri_vlanBlocks = re.finditer(rep_VLANBlocks, vlanData, re.MULTILINE)
      for vbIndex, vbMatch in enumerate(ri_vlanBlocks): 
        try:
          thisVlanBlock = vbMatch.group()
          vlanID = GetRegexGroupMatches(rep_VLANID, thisVlanBlock, 1)[0]
          m_vlanName = GetRegexGroupMatches(rep_VLANName, thisVlanBlock, 1)
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
          message = "DLink.InterfaceParser.ParseVLANDatabase() : could not parse a vlan data. Error is : {0} ".format(str(Ex))      
           
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
    if len(intfIDs) != 2 : return False
    intfModule = int(intfIDs[0])
    intfPort = int(intfIDs[1])
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
      intfInAnyRange = intfModule >= startModule and intfModule <= endModule and intfSlot <= endSlot and intfPort >= startPort and intfPort <= endPort
      if intfInAnyRange : break
      
    return intfInAnyRange
  
  def IsInterfaceTagged(self, interfaceName):
    """Determines if current VLAN is allowed and tagged on the specified interface name. Use short interface names to query"""
    return self._IsInerfaceInRange(interfaceName, self.TaggedInterfaces)
  
  def IsInterfaceUntagged(self, interfaceName):
    """Determines if current VLAN is allowed and tagged on the specified interface name. Use short interface names to query"""
    return self._IsInerfaceInRange(interfaceName, self.UntaggedInterfaces)    
    
def GetColumnValue(textLine, headerLine, headerColumn, headerSeparator, headercolumnNameIndex = 1):
  """Returns the substring from textLine in column determined by the headercolumnNameIndexposition-th position of headerColumn in headerLine"""
  headerColumnNames = map(lambda i: i.strip(), filter(None, headerLine.split(headerSeparator)))
  headerCount = len(headerColumnNames)
  requestedColumnIndex = nth_index(headerColumnNames, headerColumn, headercolumnNameIndex)
  nextColumnName = ""
  try:
    nextColumnName = headerColumnNames[ requestedColumnIndex + 1 ]
    if nextColumnName == headerColumn:
      nextColumnNameIndex = headercolumnNameIndex + 1
    else:
      nextColumnNameIndex = 1
  except:
    pass
  # Start position of substring to return from textLine
  s = findNthSubsringPosition(headerLine, headerColumn, headercolumnNameIndex)
  # End position of substring to return from textLine. Assume end of line for now
  e = len(textLine)
  if nextColumnName : 
    # Recalculate end position if we know the name of next column
    e = findNthSubsringPosition(headerLine, nextColumnName, nextColumnNameIndex)
  return textLine[s:e].strip() 
    
def nth_index(iterable, value, n):
  """Returns the position of the nth occurence of the given item in a list"""
  matches = (idx for idx, val in enumerate(iterable) if val == value)
  return next(islice(matches, n-1, n), None)
def findNthSubsringPosition(haystack, needle, n):
  """Returns the starting position of the Nth occurence of a substring in a string"""
  start = haystack.find(needle)
  while start >= 0 and n > 1:
      start = haystack.find(needle, start+len(needle))
      n -= 1
  return start
  
  
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
class DLinkSwitchType:
  Unknown = 0
  DGS3600 = 1
  DGS3100 = 2
  DGS3400 = 3
   
################### Script entry point ###################
if ConnectionInfo.Command == "CreateInstance":
  ActionResult = DLinkSwitch()
  ScriptSuccess = True
    