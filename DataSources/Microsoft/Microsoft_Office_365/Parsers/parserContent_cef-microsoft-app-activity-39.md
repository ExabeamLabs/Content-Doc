#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-39
  Product = Microsoft Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"Operation":"MoveToDeletedItems"""" ]
  Fields = ${MSParserTemplates.cef-microsoft-app-activity.Fields} [
    """"ParentFolder":.+?"Path":"\\*({object}[^"]+)"""",
    """"DestFolder":.+?"Path":"\\*({object}[^"]+)"""",
    """\Wfname=\s*({object}.+?)\s+(\w+=|$)""",
    """"target_object":"({object}[^"]+?)""""
    """sourceServiceName=({app}.+?)\s+(\w+=|$)""",
    """requestMethod=({app}.+?)\s+(\w+=|$)""",   
    """ext_userAgent_name=({resource}.+?)\s+(\w+=|$)""",
    """({activity}MoveToDeletedItems)""" 
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
    """"OriginatingServer":"({host}\w+)\s*(\([^\)]+?\))?(\\r\\n)?""""
    """CEF:([^\|"]*\|){5}({activity}[^\|"]+)""",
    """\WflexString1=({activity}[^=]+?)\.?\s+(\w+=|$)""",
    """\WdestinationServiceName=({app}[^=]+?)\s+(\w+=|$)""",
    """\Wfname=\s*({object}[^=]+?)\s+(\w+=|$)""",
    """\Wfname=\s*({file_name}[^=]+?)\s+(\w+=|$)""",
    """\Wmsg=({additional_info}[^=]+?)\s+(\w+=|$)""",
    """\Wsuser=((\w+?_)?(\w+-)?\w+-\w+-\w+-\w+|(Unknown|Microsoft Online Services|Office 365 SharePoint Online|(({domain}[^\\\s@]+)\\)?({user}[^@\s]+)|(Sync Client|Office365 Backend Process|Device Registration Service|({user_fullname}[\w,\s]+?))))\s+(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s]+@[^@\s]+)""",
    """\Wduser=({user_email}[^@\s]+@[^@\s]+)""",
    """"+UserId"+:"+({user_email}[^@\s"]+?@({email_domain}[^@\s"]+?))"+""",
    """"ClientIP":"(::1|\[?({src_ip}[A-Fa-f:\d.]+?)\]?(:({src_port}\d+)))?"""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"ResultStatus":"({result}[^"]+?)""""
  ]

```