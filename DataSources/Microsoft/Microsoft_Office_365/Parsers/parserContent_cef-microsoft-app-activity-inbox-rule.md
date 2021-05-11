#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-inbox-rule
  Product = Microsoft Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|resource-property-updated|""", """"New-InboxRule"""" ]
  Fields = ${MSParserTemplates.cef-microsoft-app-activity.Fields}[
    """"(?i)({activity}ForwardTo|delivertomailboxandforward)""""
    """"ForwardTo":"{1,20}(smtp:)?({target}[^"]+@({target_domain}[^"]+))""""
    """"SubjectOrBodyContainsWords":"({filter_key_words}[^"]+)"""
    """"ResultStatus":"({outcome}[^"]+)"""",
  ]
}
cef-microsoft-app-activity = {
  Vendor = Microsoft
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """(activityDate|env_time)":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"CreationTime\\*"{1,20}:[\s\\]*"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) [\w\-.]+ Skyformation""",
    """"OriginatingServer":"({host}\w+)\s{0,100}(\([^\)]+?\))?(\\r\\n)?"""",
    """CEF:([^\|"]*\|){5}({activity}[^\|"]+)""",
    """\WflexString1=({activity}[^=]+?)\.?\s{1,100}(\w+=|$)""",
    """"ObjectId":"(Unknown|Not Available|({object}[^"]+?))\s{0,100}"""",
    """\Wfname=\s{0,100}({object}[^=]+?)\s{1,100}(\w+=|$)""",
    """\Wfname=\s{0,100}({file_name}[^=]+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}[^=]+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=((\w+?_)?(\w+-)?\w+-\w+-\w+-\w+|(Unknown|Microsoft Intune|Microsoft Teams Services|Microsoft Online Services|Office 365 SharePoint Online|anonymous|EMPTY\.*|(({domain}[^\\\s@]+)\\)?({user}[^@\s]+)|(Sync Client|Office365 Backend Process|Device Registration Service|({user_fullname}[\w,\s]+?))))\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s]+@[^@\s]+)""",
    """"{1,20}UserId"{1,20}:"{1,20}({user_email}[^@\s"]+?@({email_domain}[^@\s"]+?))"{1,20}""",
    """"ClientIP":"(::1|\[?({src_ip}[A-Fa-f:\d.]+?)(\]:({src_port}\d{1,100}))?)"""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """"ResultStatus":"({result}[^"]+?)"""",
    """\WdestinationServiceName\s{0,100}=({app}[^=]+?)\s{1,100}(\w+=|$)""",
    """\WsourceServiceName=({app}[^=]+?)\s{1,100}(\w+=|$)""",
    """"User-Agent\\?"{1,20}:\\?"{1,20}({user_agent}[^"\\]+)"""
  ]

```