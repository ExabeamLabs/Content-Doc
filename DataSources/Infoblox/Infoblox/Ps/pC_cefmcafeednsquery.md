#### Parser Content
```Java
{
Name = cef-mcafee-dns-query
    Vendor = Infoblox
    Product = Infoblox
    Lms = ArcSight
    DataType = "dns-query"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """CEF:""", """|McAfee|ESM|""", """Infoblox_NIOS DNS Query|""", """Query\=""" ]
    Fields = [
      """({host}\S+) CEF:""",
      """CEF:([^\|]{0,2000}\|){5}({event_name}[^\|]{1,2000})""",
      """\Wrt=({time}\d{1,100})""",
      """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
      """\Wspt=({src_port}\d{1,100})""",
      """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """\Wproto=({protocol}\S+)""",
      """\W(\|_)?Query\\=({query}.*?\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|local)))""",
      """\WType_Name\\=({query_type}.+?)\s{0,100}([\w\\]{1,2000}=|$)""",
      """\WnitroRequest_Type=(-|({query_flags}.+?))\s{0,100}([\w\\]{1,2000}=|$)""",
    ]
  

}
```