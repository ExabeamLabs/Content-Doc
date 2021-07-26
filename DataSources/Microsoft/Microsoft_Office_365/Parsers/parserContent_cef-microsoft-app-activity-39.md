#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-39
  Product = Microsoft Office 365
  Conditions= [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"Operation":"MoveToDeletedItems"""" ]
  Fields = ${MSParserTemplates.cef-microsoft-app-activity.Fields} [
    """"ParentFolder":[^=]{1,2000}?"Path":"\\*({object}[^"]{1,2000})"""",
    """"DestFolder":[^=]{1,2000}?"Path":"\\*({object}[^"]{1,2000})"""",
    """fname=\s{0,100}({object}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """"target_object":"({object}[^"]{1,2000}?)""""
    """sourceServiceName=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """requestMethod=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",   
    """ext_userAgent_name=({resource}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """({activity}MoveToDeletedItems)""" 
  ]
}
cef-microsoft-app-activity = {
  Vendor = Microsoft
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """(activityDate|env_time)":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"CreationTime\\*"{1,20}:[\s\\]{0,2000}"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) [\w\-.]{1,2000} Skyformation""",
    """"OriginatingServer":"({host}\w+)\s{0,100}(\([^\)]{1,2000}?\))?(\\r\\n)?"""",
    """CEF:([^\|"]{0,2000}\|){5}({activity}[^\|"]{1,2000})""",
    """\WflexString1=({activity}[^=]{1,2000}?)\.?\s{1,100}(\w+=|$)""",
    """\WdestinationServiceName=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """"ObjectId":"(Unknown|Not Available|({object}[^"]{1,2000}?))\s{0,100}"""",
    """\Wfname=\s{0,100}({object}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wfname=\s{0,100}({file_name}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wsuser=((\w+?_)?(\w+-)?\w+-\w+-\w+-\w+|(Unknown|Microsoft Online Services|Office 365 SharePoint Online|anonymous|EMPTY\.*|(({domain}[^\\\s@]{1,2000})\\)?({user}[^@\s]{1,2000})|(Sync Client|Office365 Backend Process|Device Registration Service|({user_fullname}[\w,\s]{1,2000}?))))\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s]{1,2000}@[^@\s]{1,2000})""",
    """"{1,20}UserId"{1,20}:"{1,20}({user_email}[^@\s"]{1,2000}?@({email_domain}[^@\s"]{1,2000}?))"{1,20}""",
    """"ClientIP":"(::1|\[?({src_ip}[A-Fa-f:\d.]{1,2000}?)(\]:({src_port}\d{1,100}))?)"""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"ResultStatus":"({result}[^"]{1,2000}?)"""",
    """"User-Agent\\?"{1,20}:\\?"{1,20}({user_agent}[^"\\]{1,2000})"""
  ]

```