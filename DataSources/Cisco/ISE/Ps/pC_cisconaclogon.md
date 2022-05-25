#### Parser Content
```Java
{
Name = cisco-nac-logon
  Vendor = Cisco
  Product = ISE
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS Z"
  Conditions = [ """Acct-Status-Type=Start""", """Acct-Authentic=RADIUS""", """RADIUS Accounting start request""" ]
  Fields = [
    """CISE_RADIUS_Accounting[^,]{1,2000}?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d [+-]\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """({host}[\w\-.]{1,2000}) CISE_RADIUS_Accounting""",
    """Host:\s{0,100}({host}\S+)""",
    """, NetworkDeviceName =({network}[^,]{1,2000}),""",
    """, User-?Name =((host\/)({src_host}[^,]{1,2000})|(?!(host\/))((({domain}[^\\\/,\s@]{1,2000})[\\\/]{1,2000})?({user}[^\\\/\s,@]{1,2000}))),""",
    """, User-?Name =({user_email}[^\\\/\s,@]{1,2000}@[^\\\/\s,@]{1,2000})""",
    """, NAS-Identifier=({computer_name}[\w\-.]{1,2000})""",
    """, NAS-Identifier=({dest_host}[\w\-.]{1,2000})""",
    """, Device IP Address=({auth_server}[^,]{1,2000})""",
    """, Device IP Address=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """, Framed-IP-Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """, Called-Station-ID=(({dest_mac}([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2})|({dest_host}[\w\-.]{1,2000})):({ssid}[^,]{1,2000})""",
    """, Calling-Station-ID=(({src_mac}([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2})|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """, NetworkDeviceGroups=Location#All Locations#({location}[^,]{1,2000})""",
    """(?i)(MacAddress)=({mac_address}[^,\s]{1,2000}),""",
  ]


}
```