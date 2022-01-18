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
      """\sDeviceAddress=({host}[\w.\-]{1,2000})""",
      """\sCurrentTime=({time}\d{1,100})""",
      """\sflowStatistics\.initiatorIPAddress=({src_ip}[a-fA-F\d.:]{1,2000})""",
      """\sflowStatistics\.responderIPAddress=({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """\sflowStatistics\.initiatorPort=({src_port}\d{1,100})""",
      """\sflowStatistics\.responderPort=({dest_port}\d{1,100})""",
      """\sflowStatistics\.dnsQuery=({query}.+?)(\s{1,100}flowStatistics\.|\s{0,100}$)""",
      """\sflowStatistics\.dnsQuery=({query}.+?\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))(\s{1,100}flowStatistics\.|\s{0,100}$)""",
      """\sflowStatistics\.dnsRecordType=({dns_record_type}\d{1,100})""",
      """\sflowStatistics\.dnsResponseType=({dns_response_type}\d{1,100})""",
      """\sflowStatistics\.dnsTTL=({response_ttl}\d{1,100})""",
      """\sflowStatistics\.bytesSent=({bytes}\d{1,100})""",
    ]
  

}
```