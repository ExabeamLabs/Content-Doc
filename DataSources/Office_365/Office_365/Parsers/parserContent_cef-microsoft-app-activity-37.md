#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-37
  Product = Office 365
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """dproc=Graph Directory Audit""" ]
  Fields = ${MSParserTemplates.cef-microsoft-app-activity.Fields}[
    """\WsourceServiceName=(|({app}.+?))\s+(\w+=|$)""",
    """\Wext_result=(|({outcome}.+?))\s+(\w+=|$)""",
    """\Wext_targetResources_0__modifiedProperties_1__newValue=(|(\[|")({object}.+?)(\]|"))\s+(\w+=|$)""",
    """\Wext_targetResources_0__displayName=(|({target}.+?))\s+(\w+=|$)""",
    """\WdestinationServiceName=(|({event_subtype}.+?))\s+(\w+=|$)""",
    """\Wext_category=(|({additional_info}.+?))\s+(\w+=|$)""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]+)"""",
    """"userPrincipalName":"({user_email}[^"@\s]+@[^"@\s]+)"""",
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