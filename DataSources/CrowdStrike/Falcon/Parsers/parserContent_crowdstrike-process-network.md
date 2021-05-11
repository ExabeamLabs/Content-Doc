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
    """exabeam_host=({host}[^\s]+)""",
    """"timestamp":"({time}\d{1,100})""",
    """"LocalAddressIP4":"(0.0.0.0|0:0:0:0:0:0:0:0|({dest_ip}[A-Fa-f:\d.]+))""",
    """"LocalPort":"({dest_port}\d{1,100})""",
    """"RemoteAddressIP4":"(0.0.0.0|0:0:0:0:0:0:0:0|({dest_ip}[A-Fa-f:\d.]+))""",
    """"RemotePort":"({dest_port}\d{1,100})""",
    """"ConnectionDirection":"({direction}[^"]+)""",
    """"ContextProcessId":"({process_guid}[^"]+)""",
    """"event_simpleName":"({event_name}[^"]+)""",
    """"name":"({process_name}[^"]+)""",
    """"LocalAddressIP6":"(0.0.0.0|0:0:0:0:0:0:0:0|({dest_ip}[A-Fa-f:\d.]+))""",
    """"RemoteAddressIP6":"(0.0.0.0|0:0:0:0:0:0:0:0|({dest_ip}[A-Fa-f:\d.]+))""",
    """src-account-name":"({account_name}[^"]+)""",
  ]
}
```