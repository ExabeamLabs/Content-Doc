#### Parser Content
```Java
{
Name = crowdstrike-network-connection
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "network-connection"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"NetworkConnectIP""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"timestamp":"({time}\d+)""",
      """"event_simpleName":"({event_code}[^"]+)""",
      """"aid":"({aid}[^"]+)""",
      """"ConnectionDirection":"({direction}0).*"LocalAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|({src_ip}[^"]+)).*"LocalPort":"({src_port}\d+).*"RemoteAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|({dest_ip}[^"]+)).*"RemotePort":"({dest_port}\d+)""",
      """"ConnectionDirection":"({direction}1).*"LocalAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|({dest_ip}[^"]+)).*"LocalPort":"({dest_port}\d+).*"RemoteAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|({src_ip}[^"]+)).*"RemotePort":"({src_port}\d+)""",
      """"Protocol":"({protocol}[^"]+)""",
    ]
  }
```