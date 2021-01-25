#### Parser Content
```Java
{
Name = cisco-nac-logon
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS Z"
  Conditions = [ """Acct-Status-Type=Start""", """Acct-Authentic=RADIUS""", """RADIUS Accounting start request""" ]
  Fields = [
    """CISE_RADIUS_Accounting.+?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d [+-]\d\d:\d\d)""",
    """({host}[\w\-.]+) CISE_RADIUS_Accounting""",
    """Host:\s*({host}\S+)""",
    """, NetworkDeviceName=({network}[^,]+),""",
    """, User-?Name=(host\/)?(({domain}[^\\\/,\s@]+)[\\\/]+)?({user}[^\\\/\s,@]+),""",
    """, User-?Name=({user_email}[^\\\/\s,@]+@[^\\\/\s,@]+)""",
    """, NAS-Identifier=({computer_name}[\w\-.]+)""",
    """, Device IP Address=({auth_server}[^,]+)""",
    """, Device IP Address=({dest_ip}[a-fA-F\d.:]+)""",
    """, Framed-IP-Address=({dest_ip}[a-fA-F\d.:]+)""",
    """, Called-Station-ID=({src_host}[\w\-.]+):({ssid}[^,]+)""",
    """, Calling-Station-ID=({src_mac}[^,]+)""",
    """, NetworkDeviceGroups=Location#All Locations#({location}[^,]+)""",
    """(?i)(MacAddress)=({mac_address}[^,\s]+),""",
  ]
  DupFields = [ "computer_name->dest_host" ]
}
```