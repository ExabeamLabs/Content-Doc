#### Parser Content
```Java
{
Name = trendmicro-cef-web-activity
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss zZ"
  Conditions = [ """|Trend Micro|Control Manager|""", """|WB:36|""" ]
  Fields = [
    """\Wrt=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\w+[\+\-]\d{1,100}:\d{1,100})""",
    """({host}[\w\-.]+)\s{1,100}CEF:""",
    """\Wdvchost=({host}[^\s]+)""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wcs1=({policy}.+?)\s{1,100}\w+=""",
    """\Wrequest=(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?({web_domain}[^\\\/\s:,"]+)(:\d{1,100})?({uri_path}\/[^\s\?",]*)?({uri_query}\?[^"\s,]*)?))\s{1,100}(\w+=|$)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\WdeviceFacility=({activity}.+?)\s{1,100}(\w+=|$)""",
    """\Wrequest=[^\s]*?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|re))+)\S+\s{1,100}(\w+=|$)""",
  ]
}
```