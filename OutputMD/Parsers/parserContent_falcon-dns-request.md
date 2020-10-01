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
    Conditions = [ """"event_simpleName":""", """"DnsRequest"""", """"RequestType":""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """({host}[\w\-.]+)\s+Skyformation""",
      """"timestamp":\s*"({time}\d+)"""",
      """"DomainName":\s*"({query}[^\"]+)"""",
      """"DomainName":\s*"({query}[^\"]+\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))"""",
      """"LocalAddressIP6":\s*"({src_ip}[a-fA-F:\d.]+)""",
      """"RemoteAddressIP6":\s*"({dest_ip}[a-fA-F:\d.]+)""",
      """"LocalAddressIP4":\s*"({src_ip}[a-fA-F:\d.]+)""",
      """"RemoteAddressIP4":\s*"({dest_ip}[a-fA-F:\d.]+)""",
      """"LocalPort":\s*"({src_port}\d+)""",
      """"RemotePort":\s*"({dest_port}\d+)""",
      """"aid":\s*"({aid}[^\"]+)"""",
      """"aip":\s*"({agent_ip}[a-fA-F:\d.]+)""",
      """"event_simpleName":\s*"({event_code}[^\"]+)"""",
    ]
  }
```