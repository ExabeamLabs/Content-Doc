#### Parser Content
```Java
{
Name = cef-mcafee-skyhigh-failed-app-login
    DataType = "failed-app-login"
    Conditions = [ """|McAfee (Skyhigh)|Dashboard Audit Logs|""", """User login failed""" ]
    Fields = ${McAfeeParserTemplates.cef-mcafee-skyhigh-activity.Fields}[
      """usrName=Email\s{0,100}=\s{0,100}"{1,20}({user_email}[^"]+)"{1,20}
cef-mcafee-skyhigh-activity = {
    Vendor = McAfee
    Product = Skyhigh Networks CASB
    Lms =ArcSight
    DataType = "app-activity"
    TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
    Fields = [
      """\Wcat=(|({activity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """({host}[\w.\-]+)\s{1,100}(LEEF|CEF):""",
      """CEF:([^\|]*\|){5}({activity}[^\|]+)""",
      """({app}Skyhigh)""",
      """\W(start|devTime)=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100} \w+)""",
      """\W(suser|usrName)=(N\/A|({user_email}[^@=]+?@[^@=]+?)|({user}[^\s]+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\Wdescription=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\WobjectName=(|null|({object}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\WuserInfoEmail=(|({user_email}[^@]+({email_domain}.+?)))(\s{1,100}\w+=|\s{0,100}$)""",
      """\WuserInfoFirstName=(|({user_firstname}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\WuserInfoLastName=(|({user_lastname}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    ]

```