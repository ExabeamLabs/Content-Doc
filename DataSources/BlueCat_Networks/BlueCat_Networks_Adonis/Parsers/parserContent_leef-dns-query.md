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
      """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
      """exabeam_endTime=({time}\d{1,100})""",
      """exabeam_payload=({dest_host}[^\s]+) LEEF:""",
      """\|cat=({query_type}[^\s_]+)""",
      """src=({src_ip}[\da-fA-F\.:]+)""",
      """url=\s{0,100}({query}[^\s]+)""",
      """url=\s{0,100}([^.\s]+\.)*({top_query}[^.\s]+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)+)"""
    ]
  }
```