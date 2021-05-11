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
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
      """"timestamp":\s{0,100}"({time}\d{1,100})"""",
      """"DomainName":\s{0,100}"({query}[^\"]+)"""",
      """"DomainName":\s{0,100}"({query}[^\"]+\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))"""",
      """"LocalAddressIP6":\s{0,100}"({src_ip}[a-fA-F:\d.]+)""",
      """"RemoteAddressIP6":\s{0,100}"({dest_ip}[a-fA-F:\d.]+)""",
      """"LocalAddressIP4":\s{0,100}"({src_ip}[a-fA-F:\d.]+)""",
      """"RemoteAddressIP4":\s{0,100}"({dest_ip}[a-fA-F:\d.]+)""",
      """"LocalPort":\s{0,100}"({src_port}\d{1,100})""",
      """"RemotePort":\s{0,100}"({dest_port}\d{1,100})""",
      """"aid":\s{0,100}"({aid}[^\"]+)"""",
      """"aip":\s{0,100}"({agent_ip}[a-fA-F:\d.]+)""",
      """"event_simpleName":\s{0,100}"({event_code}[^\"]+)"""",
      """src-account-name":"({account_name}[^"]+)""",
    ]
  }
```