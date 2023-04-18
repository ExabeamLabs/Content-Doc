#### Parser Content
```Java
{
Name = cisco-nac-failed-logon
  Vendor = Cisco
  Product = ISE
  Lms = Direct
  DataType = "nac-failed-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CISE_Failed_Attempts""", """NAS-Port-Type=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """(::ffff:)?({host}[\w\-.]{1,2000}) CISE_Failed_Attempts""",
    """, (NetworkDeviceName|NetworkDeviceProfileName)=({network}[^,]{1,2000}),""",
    """, User-?Name =((::ffff:)?(host\/))?(({domain}[^\\\/,]{1,2000})[\\\/]{1,2000})?(({user_email}[^,@]{1,2000}@[^,@]{1,2000})|((([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2})|({user}[^\\\/\s,]{1,2000})))""",
    """, Device IP Address=({auth_server}[^,]{1,2000})""",
    """, NAS-IP-Address=(::ffff:)?({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """, DestinationIPAddress=(::ffff:)?({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """, Calling-Station-ID=(({src_mac}([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2})|(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(::ffff:)?({src_host}[\w\-.]{1,2000}))""",
    """, Called-Station-ID=(({dest_mac}([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2})|(::ffff:)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(::ffff:)?({dest_host}[\w\-.]{1,2000}))""",
    """, NAS-Identifier=(::ffff:)?({dest_host}[\w\-.]{1,2000})""",
    """, NAS-Identifier=({computer_name}[\w\-.]{1,2000})""",
    """, NetworkDeviceGroups=Location#All Locations#({location}[^,]{1,2000})""",
    """, FailureReason=(({result_code}\d{1,100})\s{1,100})?({failure_reason}[^,]{1,2000})""",
    """(?i)(MacAddress)=({mac_address}[^,\s]{1,2000}),""",
    """, SSID=({ssid}[^,]{1,2000})""",
    """, AuthenticationIdentityStore=({auth_server}[^,]{1,2000})""",
    """, Device IP Address=(::ffff:)?({src_ip}[^,]{1,2000}),""",
    """NAS-IP-Address=({nas_ip_address}[A-Fa-f\d:.]{1,2000})"""
  ]


}
```