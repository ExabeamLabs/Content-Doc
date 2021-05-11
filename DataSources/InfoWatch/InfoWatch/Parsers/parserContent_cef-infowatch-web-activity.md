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
    """\Wact=({action}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsntdom=({user}[^@=]+)@({domain}[^@]+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wsuser=({user}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wduser=({web_domain}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wrequest=({full_url}(\w+:\/\/)?[^\/]+?({uri_path}\/[^\?\s]*?)({uri_query}\?.*?)?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wduser=[^=]*?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wdvchost=({host}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\Wdvc=({host}.+?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",   
  ]
}
```