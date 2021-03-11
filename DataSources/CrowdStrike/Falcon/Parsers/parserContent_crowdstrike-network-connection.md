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
      """"name":"({event_name}[^"]+)"""",
      """"LocalAddressIP4":"(0.0.0.0|({src_ip}[^"]+))",("[^"]+":"[^"]+",){5}"RemotePort":"({dest_port}\d+)",("[^"]+":"[^"]+",){3,4}"LocalPort":"({src_port}\d+)",("[^"]+":"[^"]+",){6}"RemoteAddressIP4":"(0.0.0.0|({dest_ip}[^"]+))","ConnectionDirection":"({direction}0)"""",
      """"LocalAddressIP6":"(0:0:0:0:0:0:0:0|({src_ip}[^"]+))","RemoteAddressIP6":"(0:0:0:0:0:0:0:0|({dest_ip}[^"]+))",("[^"]+":"[^"]+",){3}"RemotePort":"({dest_port}\d+)",("[^"]+":"[^"]+",){3}"LocalPort":"({src_port}\d+)",("[^"]+":"[^"]+",){6}"ConnectionDirection":"({direction}0)"""",
      """"ConnectionDirection":"({direction}0).*"LocalAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|127.0.0.1|({src_ip}[^"]+)).*"LocalPort":"({src_port}\d+).*"RemoteAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|127.0.0.1|({dest_ip}[^"]+)).*"RemotePort":"({dest_port}\d+)""",
      """"ConnectionDirection":"({direction}1).*"LocalAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|127.0.0.1|({dest_ip}[^"]+)).*"LocalPort":"({dest_port}\d+).*"RemoteAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|127.0.0.1|({src_ip}[^"]+)).*"RemotePort":"({src_port}\d+)""",
      """"Protocol":"({protocol}[^"]+)""",
      """src-account-name":"({account_name}[^"]+)""",
    ]
  }
```