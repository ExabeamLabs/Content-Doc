#### Parser Content
```Java
{
Name = cef-onapsis-failed-app-login
  Product = Onapsis
  DataType = "failed-app-login"
  Conditions = [ """CEF:""", """|Onapsis|OSP|""", """|All Failed Logins|""" ]
}
cef-onapsis-activity = {
    Vendor = Onapsis
    Lms = ArcSight
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """CEF:([^\|]{0,2000}\|){5}\s{0,100}({event_name}[^\|]{1,2000}?)\s{0,100}\|""",
      """\Wend=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
      """\Wcat=(None|({category}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\Wdhost=(__EMPTY__|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\Wdpt=({dest_port}\d{1,100})""",
      """\Wspt=({src_port}\d{1,100})""",
      """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """\Wproto=(None|({protocol}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\Wreason=(None|({failure_reason}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\WrequestClientApplication=(None|({app}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\Wshost=(None|({src_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\Wsuser=(None|({user}.+?))(\s{0,100}TAG:|\s{1,100}\w+=|\s{0,100}$)""",
      """\WTAG:\s{0,100}({tag}.+?)(\s{0,100}\w+=|\s{0,100}$)""",
    ]}
```