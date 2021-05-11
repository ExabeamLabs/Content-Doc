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
    """exabeam_time=({time}\d{1,100}-\d{1,100}-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """Event-Timestamp=({time}\d{1,100})""",
    """CISE_Failed_Attempts.+?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """(::ffff:)?({host}[\w\-.]+) CISE_Failed_Attempts""",
    """, (NetworkDeviceName|NetworkDeviceProfileName)=({network}[^,]+),""",
    """, User-?Name=((::ffff:)?(host\/))?(({domain}[^\\\/,]+)[\\\/]+)?(({user_email}[^,@]+@[^,@]+)|({user}[^\\\/\s,]+))""",
    """, Device IP Address=({auth_server}[^,]+)""",
    """, NAS-IP-Address=(::ffff:)?({dest_ip}[a-fA-F\d.:]+)""",
    """, DestinationIPAddress=(::ffff:)?({dest_ip}[a-fA-F\d.:]+)""",
    """, Called-Station-ID=(::ffff:)?({src_host}[\w\-.]+):({ssid}[^,]+)""",
    """, Calling-Station-ID=(::ffff:)?({dest_host}[\w\-.]+)""",
    """, NAS-Identifier=(::ffff:)?({dest_host}[\w\-.]+)""",
    """, NAS-Identifier=({computer_name}[\w\-.]+)""",
    """, NetworkDeviceGroups=Location#All Locations#({location}[^,]+)""",
    """, FailureReason=(({result_code}\d{1,100})\s{1,100})?({failure_reason}[^,]+)""",
    """(?i)(MacAddress)=({mac_address}[^,\s]+),""",
    """, SSID=({ssid}[^,]+)""",
    """, AuthenticationIdentityStore=({auth_server}[^,]+)""",
  ]
}
```