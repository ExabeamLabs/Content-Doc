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
      """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
      """exabeam_endTime=({time}\d{1,100})""",
      """exabeam_payload=({dest_host}[^\s]{1,2000}) LEEF:""",
      """\|cat=({query_type}[^\s_]{1,2000})""",
      """src=({src_ip}[\da-fA-F\.:]{1,2000})""",
      """url=\s{0,100}({query}[^\s]{1,2000})""",
      """url=\s{0,100}([^.\s]{1,2000}\.)*({top_query}[^.\s]{1,2000}\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)+)"""
    ]
  }
```