#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-12
  Product = Microsoft Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|user-updated|""" ]
  Fields = ${MSParserTemplates.cef-microsoft-app-activity.Fields} [
    """"targetResources":[^\}]+"userPrincipalName":"({object}[^"]+)""""
  ]
}
cef-microsoft-app-activity = {
  Vendor = Microsoft
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """(activityDate|env_time)":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"CreationTime\\*"+:[\s\\]*"+({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z) [\w\-.]+ Skyformation""",
    """"OriginatingServer":"({host}\w+)\s*(\([^\)]+?\))?(\\r\\n)?"""",
    """CEF:([^\|"]*\|){5}({activity}[^\|"]+)""",
    """\WflexString1=({activity}[^=]+?)\.?\s+(\w+=|$)""",
    """\WdestinationServiceName=({app}[^=]+?)\s+(\w+=|$)""",
    """"ObjectId":"(Unknown|Not Available|({object}[^"]+?))\s*"""",
    """\Wfname=\s*({object}[^=]+?)\s+(\w+=|$)""",
    """\Wfname=\s*({file_name}[^=]+?)\s+(\w+=|$)""",
    """\Wmsg=({additional_info}[^=]+?)\s+(\w+=|$)""",
    """\Wsuser=((\w+?_)?(\w+-)?\w+-\w+-\w+-\w+|(Unknown|Microsoft Online Services|Office 365 SharePoint Online|anonymous|EMPTY\.*|(({domain}[^\\\s@]+)\\)?({user}[^@\s]+)|(Sync Client|Office365 Backend Process|Device Registration Service|({user_fullname}[\w,\s]+?))))\s+(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s]+@[^@\s]+)""",
    """"+UserId"+:"+({user_email}[^@\s"]+?@({email_domain}[^@\s"]+?))"+""",
    """"ClientIP":"(::1|\[?({src_ip}[A-Fa-f:\d.]+?)(\]:({src_port}\d+))?)"""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """"ResultStatus":"({result}[^"]+?)"""",
    """"User-Agent\\?"+:\\?"+({user_agent}[^"\\]+)"""
  ]

```