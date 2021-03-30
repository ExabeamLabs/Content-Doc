#### Parser Content
```Java
{
Name = cef-mcafee-skyhigh-failed-app-login
    DataType = "failed-app-login"
    Conditions = [ """|McAfee (Skyhigh)|Dashboard Audit Logs|""", """User login failed""" ]
    Fields = ${McAfeeParserTemplates.cef-mcafee-skyhigh-activity.Fields}[
      """usrName=Email\s*=\s*"+({user_email}[^"]+)"+,\s*Error:\s*({failure_reason}.+?)(\s+\w+=|\s*$)""",
    ]
  }
cef-mcafee-skyhigh-activity = {
    Vendor = McAfee
    Product = Skyhigh Networks CASB
    Lms =ArcSight
    DataType = "app-activity"
    TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
    Fields = [
      """\Wcat=(|({activity}.+?))(\s+\w+=|\s*$)""",
      """({host}[\w.\-]+)\s+(LEEF|CEF):""",
      """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
      """({app}Skyhigh)""",
      """\W(start|devTime)=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d+ \w+)""",
      """\W(suser|usrName)=(N\/A|({user_email}[^@=]+?@[^@=]+?)|({user}[^\s]+?))(\s+\w+=|\s*$)""",
      """\Wdescription=(|({additional_info}.+?))(\s+\w+=|\s*$)""",
      """\WobjectName=(|null|({object}.+?))(\s+\w+=|\s*$)""",
      """\WuserInfoEmail=(|({user_email}.+?))(\s+\w+=|\s*$)""",
      """\WuserInfoFirstName=(|({user_firstname}.+?))(\s+\w+=|\s*$)""",
      """\WuserInfoLastName=(|({user_lastname}.+?))(\s+\w+=|\s*$)""",
    ]

```