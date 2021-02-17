#### Parser Content
```Java
{
Name = cef-infowatch-web-activity
  Vendor = InfoWatch
  Lms = ArcSight
  DataType = "web-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Web message|""", """|DLP|DLP TM""" ]
  Fields = [
    """\Wact=({action}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wrt=({time}\d+)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsntdom=({user}[^@=]+)@({domain}[^@]+?)(\s+[\w\.]+=|\s*$)""",
    """\Wsuser=({user}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wduser=({web_domain}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wrequest=({full_url}(\w+:\/\/)?[^\/]+?({uri_path}\/[^\?\s]*?)({uri_query}\?.*?)?)(\s+[\w\.]+=|\s*$)""",
    """\Wduser=[^=]*?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(\s+[\w\.]+=|\s*$)""",
    """\Wdvchost=({host}.+?)(\s+[\w\.]+=|\s*$)""",
    """\Wdvc=({host}.+?)(\s+[\w\.]+=|\s*$)""",   
  ]
}
```