#### Parser Content
```Java
{
Name = cef-infowatch-web-activity
  Vendor = InfoWatch
  Product = InfoWatch
  Lms = ArcSight
  DataType = "web-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Web message|""", """|DLP|DLP TM""" ]
  Fields = [
    """\Wact=({action}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsntdom=({user}[^@=]{1,2000})@({domain}[^@]{1,2000}?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wsuser=({user}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wduser=({web_domain}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wrequest=({full_url}(\w+:\/\/)?[^\/]{1,2000}?({uri_path}\/[^\?\s]{0,2000}?)({uri_query}\?.*?)?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wduser=[^=]{0,2000}?({top_domain}[^\/\.\s]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wdvchost=({host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wdvc=({host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",   
  ]
}
```