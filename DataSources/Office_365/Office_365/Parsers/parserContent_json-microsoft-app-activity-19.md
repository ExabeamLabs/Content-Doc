#### Parser Content
```Java
{
Name = json-microsoft-app-activity-19
  Product = Office 365
  Conditions= [ """"Operation":"FileDeleted"""", """"Workload":"""", """"SourceFileName":"""" ]
  Fields = ${MSParserTemplates.cef-microsoft-app-activity.Fields} [
    """"ClientIP":"({src_ip}[^"]+)"""",
    """"SourceFileName":"({file_name}[^"]+)"""",
    """"SourceRelativeUrl":"({file_path}[^"]+)"""",
    """"SourceFileExtension":"({file_ext}[^"]+)"""",
    """"UserAgent":"({user_agent}[^"]+)""""
  ]
}
cef-microsoft-app-activity = {
  Vendor = Microsoft
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """(activityDate|env_time)":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"CreationTime\\*"+:[\s\\]*"+({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z) ({host}[\w\-.]+) Skyformation""",
    """"OriginatingServer":"({host}\w+)\s*(\([^\)]+?\))?(\\r\\n)?""""
    """([^\|]*\|){5}({activity}[^\|]+)""",
    """\WflexString1=({activity}.+?)\.?\s+(\w+=|$)""",
    """\WdestinationServiceName=({app}.+?)\s+(\w+=|$)""",
    """\Wfname=\s*({object}.+?)\s+(\w+=|$)""",
    """\Wfname=\s*({file_name}[^\\"]+?(\.({file_ext}[^\\\.\s"]+))?)\s+(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s+(\w+=|$)""",
    """\Wsuser=(Unknown|Microsoft Online Services|Office 365 SharePoint Online|({user}[^@\s]+)|(Sync Client|Office365 Backend Process|Device Registration Service|({user_fullname}[\w,\s]+?)))\s+(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s]+@[^@\s]+)""",
    """\Wduser=({user_email}[^@\s]+@[^@\s]+)""",
    """"+UserId"+:"+({user_email}[^@\s"]+?@[^@\s"]+?)"+""",
    """"ClientIP":"(::1|\[?({src_ip}[A-Fa-f:\d.]+?)\]?(:({src_port}\d+)))?"""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"ResultStatus":"({result}[^"]+?)""""
  ]

```