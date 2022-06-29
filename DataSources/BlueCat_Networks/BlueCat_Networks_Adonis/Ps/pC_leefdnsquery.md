#### Parser Content
```Java
{
Name = leef-dns-query
    Vendor = BlueCat Networks Adonis
  Product = BlueCat Networks Adonis
    Lms = QRadar
    DataType = "dns-query"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ "LEEF", "|DNS_Query|", "|BCN|" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """exabeam_endTime=({time}\d{1,100})""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)""",
      """exabeam_payload=({dest_host}[^\s]{1,2000}) LEEF:""",
      """\|cat=({query_type}[^\s_]{1,2000})""",
      """src=({src_ip}[\da-fA-F\.:]{1,2000})""",
      """url=\s{0,100}({query}[^\s"]{1,2000})"?""",
    ]
  

}
```