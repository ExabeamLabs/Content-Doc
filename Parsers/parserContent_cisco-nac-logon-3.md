#### Parser Content
```Java
{
Name = cisco-nac-logon-3
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS Z"
  Conditions = [ """ CISE_TACACS_Accounting """, """ TACACS+ Accounting START""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d (\+|-)\d\d:\d\d)""",
    """({host}[^\s]+)\s*CISE_TACACS_Accounting""",
    """({event_name}CISE_TACACS_Accounting)""",
    """Host:\s*({host}\S+)""",
    """, NetworkDeviceName=({network}[^,]+),""",
    """, Device IP Address=({auth_server}[^,]+)""",
    """, Device IP Address=({dest_ip}[a-fA-F\d.:]+)""",
    """, NetworkDeviceGroups=Location#All Locations#({location}[^,]+)""",
    """\sService=({service}[^,]+)""",
    """\sUser=({user}[^,]+)""",
    """\sRemote-Address=({src_ip}[^,]+)""",
    """\sPort=({src_port}\d+)""",
    """\sAuthen-Method=({auth_method}[^,]+)""",
    """\sAcsSessionID=({session_id}[^,]+)""",
  ]
}
```