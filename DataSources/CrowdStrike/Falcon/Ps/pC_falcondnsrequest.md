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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"hostname":"({host}[\w\-.]{1,2000})"""",
      """"timestamp":\s{0,100}"({time}\d{1,100})"""",
      """"DomainName":\s{0,100}"({query}[^\"]{1,2000})"""",
      """"LocalAddressIP6":\s{0,100}"({src_ip}[a-fA-F:\d.]{1,2000})""",
      """"RemoteAddressIP6":\s{0,100}"({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """"LocalAddressIP4":\s{0,100}"({src_ip}[a-fA-F:\d.]{1,2000})""",
      """"RemoteAddressIP4":\s{0,100}"({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """"LocalPort":\s{0,100}"({src_port}\d{1,100})""",
      """"RemotePort":\s{0,100}"({dest_port}\d{1,100})""",
      """"aid":\s{0,100}"({aid}[^\"]{1,2000})"""",
      """"aip":\s{0,100}"({aip}[a-fA-F:\d.]{1,2000})""",
      """"event_simpleName":\s{0,100}"({event_code}[^\"]{1,2000})"""",
      """src-account-name":"({account_name}[^"]{1,2000})""",
      """"IP4Records":"({response}[^"]{1,2000})"""",
      """"ContextProcessId":"({process_guid}[^"]{1,2000})"""",
      """"FirstIP4Record":"({dest_ip}[a-fA-F:\d.]{1,2000})""""
    ]
  

}
```