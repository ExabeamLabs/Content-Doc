#### Parser Content
```Java
{
Name = s-nac-logon-1
 Conditions = [ """Device-Administration: """, """ succeeded""" , """Protocol="""]

s-nac-logon = {
  Vendor = Cisco
  Product = Cisco ISE
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
    """User-?Name =(([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2}|({user}[^,;]{1,2000}?))(,|;)""",
    """User-?Name =(({domain}[^,;]{1,2000}?)[\\\/]{1,2000})?(([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2}|({user}[^,;\\\/@]{1,2000}))""",
    """User-?Name =([^,;]{1,2000}?[\\\/]{1,2000})?({user}[^,;\\\/@]{1,2000})@({domain}[^,;]{1,2000})""",
    """, UserName =host\/[^.]{1,2000}\.({domain}[^,]{1,2000}),\s{0,100}NAS-IP-Address""",
    """, UserName =(({user_type}host)\/)?(({domain}[^\s\\]{1,2000})\\+)?(USERNAME|([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2}|({user}[^,@]{1,2000}))""",
    """Called-Station-ID=(({dest_mac}(\w+-\w+-\w+-\w+-\w+-\w+)|([\da-fA-F]{12}))|(::ffff:)?({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|(::ffff:)?({dest_host}[\w\-.]{1,2000}))(:({ssid}[^,]{1,2000}))?,""",
    """, Calling-Station-ID=(({src_mac}([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2})|(::ffff:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(::ffff:)?({src_host}[\w\-.]{1,2000}))""",
    """AD-User-Candidate-Identities=((::ffff:)?({dest_ip}[A-Fa-f:\d.]{1,2000})|(::ffff:)?({dest_host}[\w\-.]{1,2000}))""",
    """, AD-Host-Resolved-Identities=((::ffff:)?({dest_ip}[A-Fa-f:\d.]{1,2000})|(::ffff:)?({dest_host}[^\s,]{1,2000})\s{0,100})""",
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