#### Parser Content
```Java
{
Name = s-sonicwall-vpn-start
  DataType = "vpn-start"
  Conditions = [ """msg="User login successful"""", "SSLVPN:" , "id=sslvpn"]
}

${SonicwallParserTemplates.sonicwall-vpn-login}{
  Name = s-sonicwall-vpn-start-1
  DataType = "vpn-start"
  Conditions = [ """msg="NetExtender connected"""", "SSLVPN:", "id=sslvpn"]
}

${SonicwallParserTemplates.sonicwall-vpn-login}{
  Name = s-sonicwall-vpn-end
  DataType = "vpn-end"
  Conditions = [ """msg="NetExtender disconnected""", "SSLVPN:", "id=sslvpn"]
}

${SonicwallParserTemplates.sonicwall-vpn-login}{
  Name = s-sonicwall-vpn-end-1
  DataType = "vpn-end"
  Conditions = [ """msg="User logged out""", "SSLVPN:", "id=sslvpn"]
}

${SonicwallParserTemplates.sonicwall-vpn-login}{
  Name = s-sonicwall-remote-logon
  DataType = "remote-logon"
  Conditions = [ """msg="RDP""", "SSLVPN:", "id=sslvpn"]
}

  {
    Name = s-swipes-badge-access
    Vendor = Swipes
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "yyyy/MM/dd HH:mm:ss.SSS"
    Conditions = [ """exabeam_index=swipes""" ]
    Fields = [
      """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
      """exabeam_raw=([^\|]*\|){4}({time}[^\|]+)\|""",
      """exabeam_raw=({department}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|)({last_name}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){2}({first_name}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){5}({location_area}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){6}({location_door}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){7}({badge_id}[^\|]+)\|""",
    ]
    DupFields = ["location_area->location_building"]
  }
```