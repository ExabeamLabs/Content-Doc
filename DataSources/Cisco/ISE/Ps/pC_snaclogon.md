#### Parser Content
```Java
{
Name = s-nac-logon
  Conditions = [ "Passed-Authentication: Authentication succeeded" ]

s-nac-logon = {
  Vendor = Cisco
  Product = ISE
  Lms = Splunk
  DataType = "nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "Passed-Authentication: Authentication succeeded" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s{1,100}\d{1,100}\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=(::ffff:)?({host}[^\s]{1,2000})""",
    """\s(::ffff:)?({host}(?!\d\d:\d\d:\d\d)[\w.\-]{1,2000})\s{1,100}(\S+\s{1,100}){3}(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)"""
    """\s(::ffff:)?({host}(?!\d\d:\d\d:\d\d)[\w.\-]{1,2000})\s{1,100}(\S+\s{1,100}){4}(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)"""
    """User-?Name =(USERNAME|([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2}|({user_type}host)\/({src_host}[\w\-.]{1,2000}))\s{0,100}(,|;)""",
    """User-?Name =(\$\\\{)?(([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2}|({user}[^=\s\\\/,@]{1,2000})@({domain}[^=\s\\]{1,2000})|(({=domain}[^=\s\\]{1,2000})\\{1,20})?({=user}(SVC-[^=\s\\\/.,:\{\}]{4,2000})|([^=\s\\\/.,:\{\}]{0,2000}((?i)admin))|([^=\s\\\/,:\{\}]{1,2000})))(:|(,\s))""",
    """Called-Station-ID=(({dest_mac}([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2})|(::ffff:)?({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|(::ffff:)?({dest_host}[\w\-.]{1,2000}))(:({ssid}[^,]{1,2000}))?,""",
    """, Calling-Station-ID=(({src_mac}([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2})|(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(::ffff:)?({src_host}[\w\-.]{1,2000}))""",
    """AD-User-Candidate-Identities=((::ffff:)?({dest_ip}[A-Fa-f:\d.]{1,2000})|(::ffff:)?({dest_host}[\w\-.]{1,2000})),""",
    """, AD-Host-Resolved-Identities=((::ffff:)?({dest_ip}[A-Fa-f:\d.]{1,2000})|(::ffff:)?({dest_host}[^\s,@]{1,2000})[^,]{0,100}\s{0,100})""",
    """, AD-Host-Resolved-Identities=({computer_name}[^@,]{1,2000})""",
    """, NetworkDeviceName =({network}[^,]{1,2000}),""",
    """, Device IP Address=({auth_server}[^,]{1,2000}),""",
    """, Device IP Address=(::ffff:)?({src_ip}[^,]{1,2000}),""",
    """, Framed-IP-Address=(::ffff:)?({dest_ip}[^,]{1,2000}),""",
    """DestinationIPAddress=(::ffff:)?({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """, NetworkDeviceGroups=Location#All Locations#({location}[^,]{1,2000})""",
    """(?i)(MacAddress)=({mac_address}[^,\s]{1,2000}),""",
    """NAS-IP-Address=({nas_ip_address}[A-Fa-f\d:.]{1,2000})"""
  
}
```