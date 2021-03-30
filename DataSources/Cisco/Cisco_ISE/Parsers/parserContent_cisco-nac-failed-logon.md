#### Parser Content
```Java
{
Name = cisco-nac-failed-logon
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "nac-failed-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CISE_Failed_Attempts""", """NAS-Port-Type=""" ]
  Fields = [
    """exabeam_time=({time}\d+-\d+-\d+ \d+:\d+:\d+)""",
    """Event-Timestamp=({time}\d+)""",
    """CISE_Failed_Attempts.+?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d [+-]\d\d:\d\d)""",
    """({host}[\w\-.]+) CISE_Failed_Attempts""",
    """, (NetworkDeviceName|NetworkDeviceProfileName)=({network}[^,]+),""",
    """, User-?Name=(host\/)?(({domain}[^\\\/,]+)[\\\/]+)?(({user_email}[^,@]+@[^,@]+)|({user}[^\\\/\s,]+))""",
    """, Device IP Address=({auth_server}[^,]+)""",
    """, NAS-IP-Address=({dest_ip}[a-fA-F\d.:]+)""",
    """, DestinationIPAddress=({dest_ip}[a-fA-F\d.:]+)""",
    """, Called-Station-ID=({src_host}[\w\-.]+):({ssid}[^,]+)""",
    """, Calling-Station-ID=({dest_host}[\w\-.]+)""",
    """, NAS-Identifier=({dest_host}[\w\-.]+)""",
    """, NAS-Identifier=({computer_name}[\w\-.]+)""",
    """, NetworkDeviceGroups=Location#All Locations#({location}[^,]+)""",
    """, FailureReason=(({result_code}\d+)\s+)?({failure_reason}[^,]+)""",
    """(?i)(MacAddress)=({mac_address}[^,\s]+),""",
    """, SSID=({ssid}[^,]+)""",
    """, AuthenticationIdentityStore=({auth_server}[^,]+)""",
  ]
}
```