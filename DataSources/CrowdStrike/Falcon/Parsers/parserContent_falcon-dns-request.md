#### Parser Content
```Java
{
Name = falcon-dns-request
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "dns-query"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"DnsRequest"""", """"RequestType":"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """({host}[\w\-.]+)\s+Skyformation""",
      """"timestamp":"({time}\d+)"""",
      """"DomainName":"({query}[^\"]+)"""",
      """"LocalAddressIP6":"({src_ip}[a-fA-F:\d.]+)""",
      """"RemoteAddressIP6":"({dest_ip}[a-fA-F:\d.]+)""",
      """"LocalAddressIP4":"({src_ip}[a-fA-F:\d.]+)""",
      """"RemoteAddressIP4":"({dest_ip}[a-fA-F:\d.]+)""",
      """"LocalPort":"({src_port}\d+)""",
      """"RemotePort":"({dest_port}\d+)""",
      """"aid":"({aid}[^\"]+)"""",
      """"aip":"({agent_ip}[a-fA-F:\d.]+)""",
      """"event_simpleName":"({event_code}[^\"]+)"""",
    ]
  }
```