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
    """({host}[^\s]{1,2000})\s{0,100}CISE_TACACS_Accounting""",
    """({event_name}CISE_TACACS_Accounting)""",
    """Host:\s{0,100}({host}\S+)""",
    """, NetworkDeviceName =({network}[^,]{1,2000}),""",
    """, Device IP Address=({auth_server}[^,]{1,2000})""",
    """, Device IP Address=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """, NetworkDeviceGroups=Location#All Locations#({location}[^,]{1,2000})""",
    """\sService=((?i)None|({service}[^,]{1,2000}))""",
    """\sUser=(({user_email}[^\s]{1,2000}?@[^\s]{1,2000}?)|({user}[^,]{1,2000})),""",
    """\sRemote-Address=({src_ip}[^,]{1,2000})""",
    """\sPort=({src_port}\d{1,100})""",
    """\sAuthen-Method=({auth_method}[^,]{1,2000})""",
    """\sAcsSessionID=({session_id}[^,]{1,2000})""",
  ]


}
```