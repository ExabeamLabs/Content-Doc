#### Parser Content
```Java
{
Name = outlook-exchange-app-activity-10
  Conditions = [ """Office365""",""" COMMAND=SendOnBehalf ""","""USERKEY=""","""ORGANIZATIONNAME=""","""SENDONBEHALFOFUSER=""" ]
  Fields = ${MSParserTemplates.outlook-exchange-app-activity.Fields} [ 
    """SENDONBEHALFOFUSER=({target}[^=]{1,2000}?)(\s|$)"""
  ]
  DupFields = [ "subject->object", "attachments->additional_info" ]

outlook-exchange-app-activity = {
  Vendor = Microsoft
  Product = Exchange
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w.\-]{1,2000})""",
    """TS=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """WORKLOAD=({app}[^\s]{1,2000})""",
    """USER=(({user_email}[^@\s]{1,2000}@({email_domain}[^\s@]{1,2000}))|({user}[^\s]{1,2000}))""",
    """SIP=\[*({src_ip}[A-Fa-f:\d.]{1,2000})\]{0,2000}(:({src_port}[\d]{1,2000}))?""",
    """ORIGINATINGSERVER=({src_host}[^\s]{1,2000})""",
    """LOGONUSERSID=({user_sid}[^\s]{1,2000})""",
    """COMMAND=({activity}[^\s]{1,2000})""",
    """RESULTCODE=({outcome}[^\s]{1,2000})""",
    """CLIENTPROCESSNAME=({process}[^\s]{1,2000})""",
    """Path":"({path}[^"]{1,2000}?)\s{0,100}"""",
    """"Subject":"\s{0,100}({subject}[^"}]{1,2000}?)\s{0,100}"""",
    """"Attachments\\*"{1,20}:[\s\\]{0,2000}"{1,20}\s{0,100}({attachments}[^"\\]{1,2000})\s{0,100}""",
    """"Attachments\\*"{1,20}:[\s\\]{0,2000}"{1,20}\s{0,100}({attachment}[^"\\;]{1,2000})\s{0,100}""",

}
```