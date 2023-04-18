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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """hostname":"({host}[^"]{1,2000})"""",
      """"timestamp":"({time}\d{1,100})"""",
      """"event_simpleName":"({event_code}[^"]{1,2000})""",
      """"aid":"({aid}[^"]{1,2000})""",
      """"name":"({event_name}[^"]{1,2000})"""",
      """"LocalAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|127.0.0.1|({local_ip}[^"]{1,2000}))"""
      """"RemoteAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|127.0.0.1|({remote_ip}[^"]{1,2000}))"""
      """"LocalPort":"({local_port}\d{1,100})"""
      """"RemotePort":"({remote_port}\d{1,100})"""
      """"ConnectionDirection":"({direction}(0|1))"""
     # """"LocalAddressIP4":"(0.0.0.0|({src_ip}[^"]{1,2000}))".*"RemotePort":"({dest_port}\d{1,100})".*"LocalPort":"({src_port}\d{1,100})".*"RemoteAddressIP4":"(0.0.0.0|({dest_ip}[^"]{1,2000}))".*"ConnectionDirection":"({direction}0)"""",
     #""""LocalAddressIP4":"(0.0.0.0|({dest_ip}[^"]{1,2000}))".*"RemotePort":"({src_port}\d{1,100})".*"LocalPort":"({dest_port}\d{1,100})".*"RemoteAddressIP4":"(0.0.0.0|({src_ip}[^"]{1,2000}))".*"ConnectionDirection":"({direction}1)""""
     #""""LocalAddressIP6":"(0:0:0:0:0:0:0:0|({src_ip}[^"]{1,2000}))".*"RemoteAddressIP6":"(0:0:0:0:0:0:0:0|({dest_ip}[^"]{1,2000}))".*"RemotePort":"({dest_port}\d{1,100})".*"LocalPort":"({src_port}\d{1,100})".*"ConnectionDirection":"({direction}0)"""",
     #""""LocalAddressIP6":"(0:0:0:0:0:0:0:0|({dest_ip}[^"]{1,2000}))".*"RemoteAddressIP6":"(0:0:0:0:0:0:0:0|({src_ip}[^"]{1,2000}))".*"RemotePort":"({src_port}\d{1,100})".*"LocalPort":"({dest_port}\d{1,100})".*"ConnectionDirection":"({direction}1)"""",
     #""""ConnectionDirection":"({direction}0).*"LocalAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|127.0.0.1|({src_ip}[^"]{1,2000})).*"LocalPort":"({src_port}\d{1,100}).*"RemoteAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|127.0.0.1|({dest_ip}[^"]{1,2000})).*"RemotePort":"({dest_port}\d{1,100})""",
     #""""LocalAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|127.0.0.1|({src_ip}[^"]{1,2000})).*"RemotePort":"({dest_port}\d{1,100}).*"LocalPort":"({src_port}\d{1,100}).*"RemoteAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|127.0.0.1|({dest_ip}[^"]{1,2000})).*ConnectionDirection":"({direction}0)"""
     #""""ConnectionDirection":"({direction}1).*"LocalAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|127.0.0.1|({dest_ip}[^"]{1,2000})).*"LocalPort":"({dest_port}\d{1,100}).*"RemoteAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|127.0.0.1|({src_ip}[^"]{1,2000})).*"RemotePort":"({src_port}\d{1,100})""",
     #""""LocalAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|127.0.0.1|({dest_ip}[^"]{1,2000})).*"RemotePort":"({src_port}\d{1,100}).*"LocalPort":"({dest_port}\d{1,100}).*"RemoteAddressIP(4|6)":"(0:0:0:0:0:0:0:0|0.0.0.0|127.0.0.1|({src_ip}[^"]{1,2000})).*ConnectionDirection":"({direction}1)"""
      """"Protocol":"({protocol}[^"]{1,2000})""",
      """src-account-name":"({account_name}[^"]{1,2000})""",
      """"ContextProcessId":"({process_guid}[^"]{1,2000})""""
    ]
  

}
```