#### Parser Content
```Java
{
Name = mcafee-dlp-rem-stor
  DataType = "usb-activity"
  Conditions = [ """RulesToDisplay=""", """(Removable Storage)""", """ViolationUTCTime=""", """Destination=""", """Username=""", """ViolationTimezone=""", """ViolationLocalTime=""" ]

  Fields = ${McAfeeParserTemplates.mcafee-dlp-activity.Fields} [
    """,\sDestination="{0,20}({device_type}[^"]{1,2000})"{0,20}
mcafee-dlp-activity = {
      Vendor = McAfee
      Product = McAfee DLP
      Lms = Splunk
      TimeFormat = "YYYY-MM-dd HH:mm:ss"
      Fields = [
        """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
        """,\sViolationUTCTime="{0,20}({time}\d{4}\-\d{2}\-\d{2}\s\d{2}:\d{2}:\d{2})""",
        """,\sRulesToDisplay="{0,20}({alert_name}[^"]{1,2000})"{0,20},\s""",
        """,\sName="{0,20}({src_host}[^"]{1,2000})"{0,20},\s""",
        """,\sUsername="{0,20}({user}[^"]{1,2000})"{0,20},\s""",
        """,\sFilePath="{0,20}({file_path}.+?)"{0,20},\s""",
        """,\sFileName="{0,20}({file_name}.+?)"{0,20},\s""",
        """,\sFileSize="{0,20}({bytes}\d{1,100})"{0,20}"""
        ]
    }

  cef-mcafee-skyhigh-activity = {
    Vendor = McAfee
    Product = Skyhigh Networks CASB
    Lms =ArcSight
    DataType = "app-activity"
    TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
    Fields = [
      """\Wcat=(|({activity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """({host}[\w.\-]{1,2000})\s{1,100}(LEEF|CEF):""",
      """CEF:([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
      """({app}Skyhigh)""",
      """\W(start|devTime)=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100} \w+)""",
      """\W(suser|usrName)=(N\/A|({user_email}[^@=]{1,2000}?@[^@=]{1,2000}?)|({user}[^\s]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\Wdescription=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\WobjectName=(|null|({object}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\WuserInfoEmail=(|({user_email}[^@]{1,2000}({email_domain}.+?)))(\s{1,100}\w+=|\s{0,100}$)""",
      """\WuserInfoFirstName=(|({user_firstname}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\WuserInfoLastName=(|({user_lastname}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    ]
 
```