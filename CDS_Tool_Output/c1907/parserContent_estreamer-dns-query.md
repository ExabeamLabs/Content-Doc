#### Parser Content
```Java
{
Name = estreamer-dns-query
    Vendor = Cisco
    Product = Cisco Firepower
    Lms = Direct
    DataType = "dns-query"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """DeviceType=Estreamer""", """flowStatistics.dnsQuery=""" ]
    Fields = [
      """\sDeviceAddress=({host}[\w.\-]+)""",
      """\sCurrentTime=({time}\d+)""",
      """\sflowStatistics\.initiatorIPAddress=({src_ip}[a-fA-F\d.:]+)""",
      """\sflowStatistics\.responderIPAddress=({dest_ip}[a-fA-F\d.:]+)""",
      """\sflowStatistics\.initiatorPort=({src_port}\d+)""",
      """\sflowStatistics\.responderPort=({dest_port}\d+)""",
      """\sflowStatistics\.dnsQuery=({query}.+?)(\s+flowStatistics\.|\s*$)""",
      """\sflowStatistics\.dnsQuery=({query}.+?\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))(\s+flowStatistics\.|\s*$)""",
      """\sflowStatistics\.dnsRecordType=({dns_record_type}\d+)""",
      """\sflowStatistics\.dnsResponseType=({dns_response_type}\d+)""",
      """\sflowStatistics\.dnsTTL=({response_ttl}\d+)""",
      """\sflowStatistics\.bytesSent=({bytes}\d+)""",
    ]
  }
```