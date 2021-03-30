#### Parser Content
```Java
{
Name = outlook-exchange-app-activity-9
  Conditions = ["""Office365""",""" COMMAND=SendAs ""","""USERKEY=""","""ORGANIZATIONNAME=""","""SENDASUSER=""" ]
  Fields = ${MSParserTemplates.outlook-exchange-app-activity.Fields} [
    """SENDASUSER=({target}[^\s]+)""",
  ]
  DupFields = [ "subject->object", "attachments->additional_info" ]
}
outlook-exchange-app-activity = {
  Vendor = Microsoft
  Product = Exchange
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w.\-]+)""",
    """TS=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """WORKLOAD=({app}[^\s]+)""",
    """USER=(({user_email}[^@\s]+@({email_domain}[^\s@]+))|({user}[^\s]+))""",
    """SIP=\[*({src_ip}[A-Fa-f:\d.]+)\]*(:({src_port}[\d]+))?""",
    """ORIGINATINGSERVER=({src_host}[^\s]+)""",
    """LOGONUSERSID=({user_sid}[^\s]+)""",
    """COMMAND=({activity}[^\s]+)""",
    """RESULTCODE=({outcome}[^\s]+)""",
    """CLIENTPROCESSNAME=({process}[^\s]+)""",
    """Path":"({path}[^"]+?)\s*"""",
    """"Subject":"\s*({subject}[^"}]+?)\s*"""",
    """"Attachments\\*"+:[\s\\]*"+\s*({attachments}[^"\\]+)\s*""",
    """"Attachments\\*"+:[\s\\]*"+\s*({attachment}[^"\\;]+)\s*""",
]

```