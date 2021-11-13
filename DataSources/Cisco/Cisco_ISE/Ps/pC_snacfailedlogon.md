#### Parser Content
```Java
{
Name = s-nac-failed-logon
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Splunk
  DataType = "nac-failed-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "CISE_Failed_Attempts", "since user has entered the wrong password" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({host}[\w\-.]{1,2000})\s{1,100}CISE_Failed_Attempts""",
    """\d{1,100}\s{1,100}({time}\d\d\d\d\-\d\d\-\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """, UserName =(({user_type}host)\/)?(({domain}[^\s\\]{1,2000})\\+)?(({user_email}[^,@]{1,2000}@[^,@]{1,2000})|({user}[^,]{1,2000}))""",
    """, Calling-Station-ID=({dest_host}[^,]{1,2000})""",
    """, Called-Station-ID=({src_host}[^,]{1,2000}):({ssid}[^,]{1,2000})""",
    """, AD-Host-Resolved-Identities=({dest_host}[^@,]{1,2000})""",
    """, AD-Host-Resolved-Identities=({computer_name}[^@,]{1,2000})""",
    """, (NetworkDeviceName|NetworkDeviceProfileName)=({network}[^,]{1,2000})""",
    """, Device IP Address=({auth_server}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """, Device IP Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """, Framed-IP-Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """, DestinationIPAddress=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """, NetworkDeviceGroups=Location#All Locations#({location}[^,]{1,2000})""",
    """, FailureReason=({result_code}\d{1,100})""",
    """, FailureReason=\d{1,100} ({failure_reason}[^,]{1,2000})""",
    """(?i)(MacAddress)=({mac_address}[^,\s]{1,2000}),""",
    """, SSID=({ssid}[^,]{1,2000})""",
    """, AuthenticationIdentityStore=({auth_server}[^,]{1,2000})""",
  ]


}
```