##########################################################################
#                                                                        #
#  This file is a Python parser module for Script N'Go Network Map and   #
#  is written to parse the configuration on specific Hirschmann switches.#
#                                                                        #
#  You may not use this file without a valid Script N'Go license.        #
#  You may not duplicate or create derivative work from this script      #
#  without a valid Script N'Go license.                                  #
#                                                                        #
#  Copyright Eszközbeszerzés Kft. (c) 2020                               #
#                                                                        #
##########################################################################

import clr
clr.AddReferenceToFileAndPath("SNGInterfaces.dll")
clr.AddReferenceToFileAndPath("NetworkMap.dll")
clr.AddReferenceToFileAndPath("Common.dll")
import L3Discovery
import Scriptngo.Common
import re
from System.Diagnostics import DebugEx, DebugLevel
from System.Net import IPAddress
from L3Discovery import NeighborProtocol
from Scriptngo.Common import IPOperations
# last changed : 2020.04.14
scriptVersion = "9.0.0"
class HirshmannSwitchType:
  Unknown = 0
  MachSwitch = 1
  RailSwitch = 2
  
class HirshmannSwitch(L3Discovery.IRouter):
  # Beyond _maxRouteTableEntries only the default route will be queried
  _maxRouteTableEntries = 10000    
  
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
    # The default routing instance name. Set ing Initialize()
    self._defaultRoutingInstanceName = "Default"
    # The dictionary of RoutingInstances keyed by LogicalSystem name
    self._routingInstances = {}
    # The routing protocols run by this router, dictionary keyed by routing instamce name
    self._runningRoutingProtocols = {} 
    # The current PGT settings   
    self.ScriptSettings = Scriptngo.Common.SettingsManager.GetCurrentScriptSettings()
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
    # Identifies the switch type as MACH or RailSwitch
    self.SwitchType = HirshmannSwitchType.Unknown     
      
  def GetHostName(self):
    """ Returns the host bane as a string"""
    if not self._hostName :
      v = self.GetVersion()
      rep_SystemName = r"^System Name\.+(.*)"
      try:
        self._hostName = GetRegexGroupMatches(rep_SystemName, v, 1)[0].strip()
      except Exception as Ex:
        DebugEx.WriteLine("HirschmannMACH.GetHostName() : unexpected error : {0}".format(str(Ex)))      
    return self._hostName
    
  def GetInventory(self):
    """Returns the device inventory string"""
    if self.SwitchType == HirshmannSwitchType.MachSwitch:
      # regex group 1 : Power Supply Information    
      rep_PSInfo = r"power supply information:([\s\S]+(?=media module information))"
      # regex group 1 : Media Module Information
      rep_MMInfo = r"media module information:([\s\S]+(?=sfp information))"
      # regex group 1 : Media Module Information
      rep_SFPInfo = r"sfp information[\w\s\S]+:([\s\S]+(?=^CPU))"
      v = self.GetVersion()
      inventoryText = "unknown"
      try:
        PSInfo = GetRegexGroupMatches(rep_PSInfo, v, 1)[0]
        MMInfo = GetRegexGroupMatches(rep_MMInfo, v, 1)[0]
        SFPInfo = GetRegexGroupMatches(rep_SFPInfo, v, 1)[0]
        inventoryText = "\r\n".join([PSInfo, MMInfo, SFPInfo])
      except Exception as Ex:
        DebugEx.WriteLine("HirschmannMACH.GetInventory() : unexpected error : {0}".format(str(Ex)))
      return inventoryText
    elif self.SwitchType == HirshmannSwitchType.RailSwitch:
      # regex group 1 : Power Supply Information    
      rep_PSInfo = r"power supply.*"
      # regex group 1 : Media Module Information
      rep_MMInfo = r"media module information.*"
      v = self.GetVersion()
      inventoryText = "unknown"
      try:
        PSInfo = "\r\n".join(re.findall(rep_PSInfo, v, re.IGNORECASE))
        MMInfo = "\r\n".join(re.findall(rep_MMInfo, v, re.IGNORECASE))
        inventoryText = "\r\n".join([PSInfo, MMInfo])
      except Exception as Ex:
        DebugEx.WriteLine("HirschmannMACH.GetInventory() : unexpected error : {0}".format(str(Ex)))
      return inventoryText    
    
  def GetLogicalSystemNames(self):
    """ Returns the list of Logical Systems as a string list"""
    return self._logicalSystems
    
  def GetManagementIP(self):
    """Returns the management ip address as a string"""
    sysIP =  ConnectionInfo.DeviceIP
    v = self.GetVersion()
    rep_SystemIP = r"system ip address\.+(.*)"
    try:
      sysIP = GetRegexGroupMatches(rep_SystemIP, v, 1)[0].strip()
    except Exception as Ex:
      DebugEx.WriteLine("HirschmannMACH.GetManagementIP() : unexpected error : {0}".format(str(Ex)))
    return sysIP
    
  def GetModelNumber(self):
    """Returns Model number as a string, calculated from Inventory"""
    if not self._ModelNumber :
      v = self.GetVersion()
      if self.SwitchType == HirshmannSwitchType.MachSwitch:
        rep_Backplane = r"Backplane Hardware Description\.+(.*)"
      elif self.SwitchType == HirshmannSwitchType.RailSwitch:
        rep_Backplane = r"Hardware Description\.+(.*)"
      try:
        self._ModelNumber = GetRegexGroupMatches(rep_Backplane, v, 1)[0].strip()
      except Exception as Ex:
        DebugEx.WriteLine("HirschmannMACH.GetModelNumber() : unexpected error : {0}".format(str(Ex)))
    return self._ModelNumber
    
  def GetOperationStatusLabel(self):
    """Returns a string describibg current activity"""
    return self._operationStatusLabel
    
  def GetPlatform(self):
    """Return a string	to describe device Platform"""
    return "Hirschmann MACH"
    
  def GetSession(self):
    """Returns the actual Session object"""
    return Session
    
  def GetStackCount(self):
    """Returns the number of members in a switch stack"""
    return 1
    
  def GetSupportTag(self):
    """Returns a string describing capability of this instance"""
    global scriptVersion
    return "Hirschmann swith support module - Python Parser v{0}".format(scriptVersion)
    
  def GetSupportedEngineVersion(self):
    """Returns the regex pattern covering supported Discovery Engine versions"""
    global scriptVersion
    return r"^7\.5.*"
    
  def GetSystemSerial(self):
    """Returns System serial numbers as a string, calculated from Inventory"""
    if not self._SystemSerial :
      v = self.GetVersion()
      if self.SwitchType == HirshmannSwitchType.MachSwitch:
       rep_BackplaneSerial = r"^Serial Number \(Backplane\)\.+(.*)"
      elif self.SwitchType == HirshmannSwitchType.RailSwitch :
        rep_BackplaneSerial = r"^Serial Number\.+(.*)"
      try:
        self._SystemSerial = GetRegexGroupMatches(rep_BackplaneSerial, v, 1)[0].strip()
      except Exception as Ex:
        DebugEx.WriteLine("HirschmannMACH.GetSystemSerial() : unexpected error : {0}".format(str(Ex)))
    return self._SystemSerial
    
  def GetSystemMAC(self, instance):
    """Returns the MAC addresses associated with the local system for the given routing instance"""
    systemMAC = ""
    v = self.GetVersion()
    rep_BackplaneMAC = r"^Base MAC Address(?:.+\.)\s(.*)"
    try:
      systemMAC = GetRegexGroupMatches(rep_BackplaneMAC, v, 1)[0].strip()
    except Exception as Ex:
      DebugEx.WriteLine("HirschmannMACH.GetSystemMAC() : unexpected error : {0}".format(str(Ex)))
    return systemMAC
      
  def GetDeviceType(self):
    """Returns Type string that can be Switch, Router or Firewall, depending on Model"""
    return "Switch"
    
  def GetVendor(self):
    """Must return a string matching the Vendor name this parser is responible for"""
    return "Hirschmann"
    
  def GetVersion(self):
    """Must return device version string 	"""
    if not self._versionInfo:
      self._versionInfo = Session.ExecCommand("show sysinfo")
    return self._versionInfo
  
  def ActiveProtocols(self, instance):
    """Returns the list of NeighborProtocols running on the requested routing instance """
    # no routing instances supported here
    instanceName = self._defaultRoutingInstanceName
    if instance : instanceName = instance.Name
    if self._runningRoutingProtocols.get(instanceName, None) == None:
      self._runningRoutingProtocols[instanceName] = []
    if len(self._runningRoutingProtocols[instanceName]) == 0 :
      # OSPF
      cmd = "show ip ospf"
      response = Session.ExecCommand(cmd)
      rep_ospfEnabled = r"^OSPF Admin Mode\.+(.*)"
      try:
        ospfStatus = GetRegexGroupMatches(rep_ospfEnabled, response, 1)[0].strip().lower()
        if not ("disable" in ospfStatus) :
          self._runningRoutingProtocols[instanceName].Add(L3Discovery.NeighborProtocol.OSPF)
      except Exception as Ex:
        DebugEx.WriteLine("HirschmannMACH.ActiveProtocols() : unexpected error parsing OSPF protocol information : {0}".format(str(Ex)))
      # RIP
      cmd = "show ip rip"
      response = Session.ExecCommand(cmd)
      rep_ripEnabled = r"^RIP Admin Mode\.+(.*)"
      try:
        ripStatus = GetRegexGroupMatches(rep_ripEnabled, response, 1)[0].strip().lower()
        if not ("disable" in ripStatus) :
          self._runningRoutingProtocols[instanceName].Add(L3Discovery.NeighborProtocol.RIP)
      except Exception as Ex:
        DebugEx.WriteLine("HirschmannMACH.ActiveProtocols() : unexpected error parsing RIP protocol information : {0}".format(str(Ex)))
      # STATIC 
      cmd = "show ip route static"
      response = Session.ExecCommand(cmd)
      rep_ipAddress = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
      try:
        foundAddresses = re.findall(rep_ipAddress, response)
        # TODO : this may be too simple
        if len(foundAddresses) > 0 :
          self._runningRoutingProtocols[instanceName].Add(L3Discovery.NeighborProtocol.STATIC)
      except Exception as Ex:
        DebugEx.WriteLine("HirschmannMACH.ActiveProtocols() : unexpected error parsing STATIC routing information : {0}".format(str(Ex)))
 
      # LLDP - only for default instance
      cmd = "show lldp config chassis admin-state"
      response = Session.ExecCommand(cmd)
      rep_lldpEnabled = r"^LLDP Config. Chassis,\s+Admin State\.+(.*)"
      try:
        lldpStatus = GetRegexGroupMatches(rep_lldpEnabled, response, 1)[0].strip().lower()
        if "on" in lldpStatus :
          self._runningRoutingProtocols[instanceName].Add(L3Discovery.NeighborProtocol.LLDP)
      except Exception as Ex:
        DebugEx.WriteLine("HirschmannMACH.ActiveProtocols() : unexpected error parsing LLDP protocol information : {0}".format(str(Ex)))
    result =  self._runningRoutingProtocols[instanceName]
    return result
    
  def BGPAutonomousSystem(self, instance):
    """Returns the BGP AN number for the requested routing instance"""
    # BGP is not supported for this device
    return ""
    
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
    
    if "hirschmann mach" in v.lower() : 
      self.SwitchType = HirshmannSwitchType.MachSwitch
    if "hirschmann railswitch" in v.lower() : 
      self.SwitchType = HirshmannSwitchType.RailSwitch
    accepted = self.SwitchType != HirshmannSwitchType.Unknown
    if accepted:
      # We use Session variable because its type is know at design time and code completion works, but session would be the same as Session
      Session.ExecCommand("enable")
    return accepted
    
  def RegisterNHRP(self, neighborRegistry, instance):
    """Collects NHRP protocol information and registers it with Network Discovery Engine"""
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
    self.ScriptSettings = Scriptngo.Common.SettingsManager.GetCurrentScriptSettings()
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
    """Returns the list of RoutingInstance objects for the VRFs running on the requested logical system"""
    if not logicalSystemName : 
      logicalSystemName = "Default"
    if self._routingInstances.get(logicalSystemName, None) == None : 
      self._routingInstances[logicalSystemName] = []
      
    if len(self._routingInstances[logicalSystemName]) == 0:
      instances = []
      # This Hirschmann switch does not support VRFs, so add the default (global) instance only
      defInstance = L3Discovery.RoutingInstance()
      defInstance.LogicalSystemName = logicalSystemName
      defInstance.DeviceVendor = self.GetVendor()
      defInstance.Name = self._defaultRoutingInstanceName
      instances.append(defInstance)
      self._routingInstances[logicalSystemName] = instances
    
    result = self._routingInstances[logicalSystemName]
    return result
    
  def RouteTableSize(self, instance):
    """Returns the size of the route table for the requested routing instance"""
    routeTableSize = -1
    # Not implemented
    return routeTableSize
      
  def RoutingTable(self, instance):
    """Returns the list of RouteTableEntry objects for requested RoutingInstance"""
    parsedRoutes = []
    # Not implemented
    return parsedRoutes
      
class RouterIDCalculator():
  """Performs Router ID and AS Number calculations """
  def __init__(self, router):
    # self.Router will hold a reference to the parent router instance
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
    globalRouterID = self.Router.GetManagementIP()
    # BGP is not supported on this device
    self.BGPASNumber[instanceName] = ""
    # get the running routing protocols for this routing instance
    runnintRoutingProtocols = self.Router.ActiveProtocols(instance)
    for thisProtocol in runnintRoutingProtocols:  
      if thisProtocol == L3Discovery.NeighborProtocol.OSPF:
        cmd = "show ip ospf"
        ospfGeneral = Session.ExecCommand(cmd)
        # expecting output like this:
        #(Hirschmann MACH4002) >show ip ospf 
        #
        #Router ID...................................... 0.0.0.0
        #OSPF Admin Mode................................ Disable
        #ASBR Mode...................................... Disable
        #RFC 1583 Compatibility......................... Enable
        #
        #OSPF must first be initialized for the switch.
        #        
        rep_ospfRouterID = r"^Router ID\.+\s(.*)"        
        match = GetRegexGroupMatches(rep_ospfRouterID, ospfGeneral, 1)
        if len(match) == 1 :
          self.RouterID[instanceName][str(thisProtocol)] = match[0].strip()
          if globalRouterID == ConnectionInfo.DeviceIP : globalRouterID = match[0]
     
      elif thisProtocol == L3Discovery.NeighborProtocol.LLDP:
        # for LLDP report the system name as router id
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
    #  self.Router will hold a reference to the parent router instance
    self.Router = router
    # These are the list of interfaces collected by ParseInterfaces() method. 
    # A dictionary, keyed by routing instance name and containing Lists
    self.Interfaces = {}
    # Interface config cache. 
    # A dictionary keyed by Interface Name and containing strings
    self._interfaceConfigurations = {}
    # The running configuration of router
    self._running_config = None
    # VLAN database dictionary containing vlan Names keyed by VLAN ID
    self._vlanNames = {}
    # VLAN database dictionary containing vlan IDs keyed by VLAN Name
    self._vlanIDs = {}
    
  def ParseInterfaces(self, instance) :
    """Collects interface details for all interfaces of specified routing instance, but do not collect interface configuration """
    from  Scriptngo.Common import IPOperations
    try:
      # First parse the VLAN database if missing
      if len(self._vlanIDs) == 0 : self.ParseVLANDatabase()
      # Then collect the interfaces configurations if not yet done
      if len(self._interfaceConfigurations) == 0 : self.ParseInterfaceConfigurations()
      # Init interface dictionary for current routing instance
      instanceName = self.Router._defaultRoutingInstanceName
      if instance : instanceName = instance.Name
      if self.Interfaces.get(instanceName, None) == None:
        self.Interfaces[instanceName] = []
      if self.Router.SwitchType == HirshmannSwitchType.MachSwitch: 
        # get vlan-ip data
        vlanRoutedInterfaces = Session.ExecCommand("show ip vlan").splitlines()
        # expected output for vlanRoutedInterfaces :
        #           Logical                                                       
        #VLAN ID   Interface     IP Address       Subnet Mask        MAC Address  
        #-------  -----------  ---------------  ---------------  -----------------
        #1        9/7          10.0.40.254      255.255.255.0    EC:74:BA:50:0B:49
        #2        9/1          10.0.41.254      255.255.255.0    EC:74:BA:50:0B:43
        #3        9/2          10.0.39.254      255.255.255.0    EC:74:BA:50:0B:44
        #4        9/3          10.0.43.254      255.255.255.0    EC:74:BA:50:0B:45
        #5        9/4          10.0.38.254      255.255.255.0    EC:74:BA:50:0B:46
        vlanIPHeaderLine = next((l for l in vlanRoutedInterfaces if l.startswith("----")), None)
        # vlanHeaderSection will contain column start-end positions
        vlanIPHeaderSection = []
        if vlanIPHeaderLine : 
          matches = re.finditer(r"-  -", vlanIPHeaderLine)
          for index, match in enumerate(matches):
            frompos = match.regs[0][0]
            topos = match.regs[0][1]
            #print "{0}:{1}".format(frompos, topos)
            if index == 0:
              vlanIPHeaderSection.append([0, frompos + 1])
            else:
              vlanIPHeaderSection[index][1] = topos - 2
            vlanIPHeaderSection.append([topos-1, -1])
          if len(vlanIPHeaderSection) > 0 : vlanIPHeaderSection[-1][1] = len(vlanIPHeaderLine)      
      
      # get all interface data
      responseLines = Session.ExecCommand("show port all").splitlines()
      # expected output responseLines :
      #               Admin   Physical   Physical   Link   Link   Cable-Cross   Flow   Device  VLAN
      # Intf   Type    Mode    Mode       Status   Status  Trap   PhysMode Fix  Mode   status  Prio
      #------ ------ ------- ---------- ---------- ------ ------- ------------ ------- ------- ----
      #6/1           Enable  Auto       1000 Full  Up     Enable  Unsupported  Enable  Ignore     0
      #6/2           Enable  Auto       1000 Full  Up     Enable  Unsupported  Enable  Ignore     0
      #
      interfaceLines = [l.strip() for l in responseLines if len(re.findall(r"^\d+\/\d+\s+", l)) > 0]
      headerLine = next((l for l in responseLines if l.startswith("----")), None)
      # headerSection will contain column start-end positions
      headerSections = []
      matches = re.finditer(r"- -", headerLine)
      for index, match in enumerate(matches):
        frompos = match.regs[0][0]
        topos = match.regs[0][1]
        #print "{0}:{1}".format(frompos, topos)
        if index == 0:
          headerSections.append([0, frompos + 1])
        else:
          headerSections[index][1] = topos - 2
        headerSections.append([topos-1, -1])
      headerSections[-1][1] = len(headerLine)
      # --
      for line in interfaceLines:
        try:
          ri = L3Discovery.RouterInterface()
          ri.Name = line[headerSections[0][0]:headerSections[0][1]].strip()
          adminMode = line[headerSections[2][0]:headerSections[2][1]].strip().lower()
          if adminMode == "enable": adminMode = "up"
          else: adminMode = "down"
          linkState = line[headerSections[5][0]:headerSections[5][1]].strip().lower()
          ri.Status = "{0}/{1}".format(linkState, adminMode)
          ri.PortMode = L3Discovery.RouterInterfacePortMode.Access
          ri.Configuration = self._interfaceConfigurations.get(ri.Name, "")
          ri.Address = ""
          if "ip address" in ri.Configuration:
            addressline = next((l for l in ri.Configuration.splitlines() if l.startswith("ip address")), "")
            if addressline:
              prefixAndMask = GetIPAddressAndSubnetMaskFromLine(addressline)
              if prefixAndMask:
                prefix = prefixAndMask[0]
                ri.Address = prefix
                maskLength = str(IPOperations.GetMaskLength(prefixAndMask[1]))
                ri.MaskLength = maskLength
                ri.PortMode = L3Discovery.RouterInterfacePortMode.Routed
                # try to get which VLAN this interface belongs to, if any
                for vlanLine in vlanRoutedInterfaces :
                  vlanIntfName = vlanLine[vlanIPHeaderSection[1][0]:vlanIPHeaderSection[1][1]].strip()
                  if vlanIntfName == ri.Name :
                    thisIntfVlanID = vlanLine[vlanIPHeaderSection[0][0]:vlanIPHeaderSection[0][1]].strip()
                    if thisIntfVlanID.isdigit():
                      intfVLANinfo = ""
                      vname = self._vlanNames.get(thisIntfVlanID, "")
                      if vname : intfVLANinfo = "{0}|{1}".format(vname, thisIntfVlanID)
                      else : intfVLANinfo = thisIntfVlanID
                      ri.VLANS = intfVLANinfo
                    
          # process interface vlan membership
          if ri.PortMode != L3Discovery.RouterInterfacePortMode.Routed and ri.Configuration :
            try:
              pvid = ""
              rep_pvid = r"vlan pvid (\d+)"   
              ri_pvid = re.finditer(rep_pvid, ri.Configuration, re.MULTILINE | re.IGNORECASE)
              for i, m in enumerate(ri_pvid):
                pvid = m.group(1)
              taggedVLANs = []
              rep_taggedVLANs = r"vlan tagging (\d+)" 
              ri_taggedVLANs = re.finditer(rep_taggedVLANs, ri.Configuration, re.MULTILINE | re.IGNORECASE)
              for i, m in enumerate(ri_taggedVLANs):
                vid = m.group(1)
                vname = self._vlanNames.get(vid, "")
                if vname : taggedVLANs.append("{0}|{1}".format(vname, vid))
                else : taggedVLANs.append(vid)
              if len(taggedVLANs) > 0 : ri.PortMode = L3Discovery.RouterInterfacePortMode.Trunk
              interfaceVLANInfo = ",".join(taggedVLANs)
              if pvid :
                pvidname = self._vlanNames.get(pvid, "")
                if pvidname : interfaceVLANInfo += ",{0}|{1}".format(pvidname, pvid)
                else : interfaceVLANInfo += ",{0}".format(pvid)
              ri.VLANS = interfaceVLANInfo.strip(',')  
            except Exception as Ex:
              DebugEx.WriteLine("HirschmannMACH.InterfaceParser.ParseInterfaces() : unexpected error procesing VLAN data for interface: {0}. Error is : {1}".format(ri.Name, str(Ex)))
          self.Interfaces[instanceName].Add(ri)
        except Exception as Ex:
          DebugEx.WriteLine("HirschmannMACH.InterfaceParser.ParseInterfaces() : unexpected error procesing interface data: {0}".format(str(Ex)))
    except Exception as Ex:
      DebugEx.WriteLine("HirschmannMACH.InterfaceParser.ParseInterfaces() : unexpected error : {0}".format(str(Ex)))        
        
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
    # initialize instance interfaces if missing
    if self.Interfaces.get(instanceName, None) == None:
      self.Interfaces[instanceName] = [] 
    # check interface list for this instance
    instanceInterfaces = self.Interfaces[instanceName]
    if len(instanceInterfaces) == 0 : 
      self.ParseInterfaces(instance)
      instanceInterfaces = self.Interfaces[instanceName]
    foundInterface = next((intf for intf in instanceInterfaces if intf.Name == ifName.strip()), None)
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
          
    self._interfaceConfigurations = {}
    currentIntfName = ""
    currentIntfConfig = []
    intfConfigBlock = False
    for thisLine in self._running_config.splitlines():
      try:
        words = filter(None, thisLine.split(" "))
        rep_IntfLine = r"(?<=^interface)\s+(\d+\/\d+)"
        m_intfLine = re.findall(rep_IntfLine, thisLine, re.IGNORECASE)
        if len(m_intfLine):
          # This should be a new interface definition
          currentIntfConfig = []
          currentIntfName = m_intfLine[0].strip()
          intfConfigBlock = True
        elif intfConfigBlock :
          sline = thisLine.strip()
          if sline and sline != "exit" :
            currentIntfConfig.append(sline)
          if sline == "exit" and currentIntfName :
             # add the interface config
            self._interfaceConfigurations[currentIntfName] = "\r\n".join(currentIntfConfig)  
            intfConfigBlock = False         
      except Exception as Ex:
        message = "Hirschmann.InterfaceParser.ParseInterfaceConfigurations() : could not parse an interface configuration for line <{0}>. Error is : {1} ".format(thisLine, str(Ex))
        DebugEx.WriteLine(message)    
      
  def ParseVLANDatabase(self):
    """Populates vlanNames and vlanIDs dictionaries by parsing switch vlan database"""
    self._vlanIDs = {}
    self._vlanNames = {}
    rep_VLAN = r"^(\d+)(?:\s+)(\w+)"
    vlanData = Session.ExecCommand("show vlan brief")
    ri_vlanData = re.finditer(rep_VLAN, vlanData, re.MULTILINE | re.IGNORECASE)
    for index, match in enumerate(ri_vlanData):
      try:
        vlanID = match.group(1)
        vlanName = match.group(2)
        self._vlanIDs[vlanName] = vlanID
        self._vlanNames[vlanID] = vlanName
      except Exception as Ex:
        message = "Hirschmann.InterfaceParser.ParseInterfaceConfigurations() : could not parse a vlan data. Error is : {0} ".format(str(Ex))
      
           
  def IsInterrestingInterface(self, intfName):
    """ Determines if a given name is an interface name we want to parse"""
    iname = intfName.lower()
    return iname.startswith("fastethernet") or iname.startswith("gigabitethernet") or iname.startswith("tengigabitethernet") or iname.startswith("ethernet") or iname.startswith("loopback") or iname.startswith("vlan") or iname.startswith("tunnel")
      
  def Reset(self) :
    self.Interfaces = {}
    self._interfaceConfigurations = {}
    self._running_config = None
    self._vlanIDs = {}
    self._vlanNames = {}
  
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
  ActionResult = HirshmannSwitch()
  ScriptSuccess = True
    