#### Parser Content
```Java
{
Name = crowdstrike-process-network
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "process-network"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """"event_simpleName":"""", """NetworkListenIP""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"timestamp":"({time}\d{1,100})""",
    """"LocalAddressIP4":"(0.0.0.0|0:0:0:0:0:0:0:0|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """"LocalPort":"({dest_port}\d{1,100})""",
    """"RemoteAddressIP4":"(0.0.0.0|0:0:0:0:0:0:0:0|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """"RemotePort":"({dest_port}\d{1,100})""",
    """"ConnectionDirection":"({direction}[^"]{1,2000})""",
    """"ContextProcessId":"({process_guid}[^"]{1,2000})""",
    """"event_simpleName":"({event_name}[^"]{1,2000})""",
    """"name":"({process_name}[^"]{1,2000})""",
    """"LocalAddressIP6":"(0.0.0.0|0:0:0:0:0:0:0:0|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """"RemoteAddressIP6":"(0.0.0.0|0:0:0:0:0:0:0:0|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """src-account-name":"({account_name}[^"]{1,2000})""",
  ]
}
```