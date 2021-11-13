#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-3
  Product = Office 365
  Conditions= [ """CEF:""", """destinationServiceName =Office 365""", """"Delete group""" ]

cef-microsoft-app-activity = {
  Vendor = Microsoft
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}\S{1,2000})""",
    """activityDate":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """env_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"CreationTime\\*"{1,20}:[\s\\]{0,2000}"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) [\w\-.]{1,2000} Skyformation""",
    """"OriginatingServer":"({host}\w+)\s{0,100}(\([^\)]{1,2000}?\))?(\\r\\n)?"""",
    """CEF:([^\|"]{0,2000}\|){5}({activity}[^\|"]{1,2000})""",
    """\sflexString1=({activity}[^=]{1,2000}?)\.?\s{1,100}(\w+=|$)""",
    """"ObjectId":"(Unknown|Not Available|({object}[^"]{1,2000}?))\s{0,100}"""",
    """\sfname=\s{0,100}({object}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\sfname=\s{0,100}({file_name}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\ssuser=((\w+?_)?(\w+-)?\w+-\w+-\w+-\w+|(Unknown|Microsoft Intune|Microsoft Teams Services|Microsoft Online Services|Office 365 SharePoint Online|anonymous|EMPTY\.*|({user_email}[^@\s"]{1,2000}@[^@\s\."]{1,2000}\.[^\s",]{1,2000})|(({domain}[^\\\s@]{1,2000})\\)?(system|({user}[^@\s]{1,2000}))|(Sync Client|Office365 Backend Process|Device Registration Service|({user_fullname}[\w,\s]{1,2000}?))))\s{1,100}(\w+=|$)""",
    """"{1,20}UserId"{1,20}:"{1,20}({user_email}[^@\s"]{1,2000}?@({email_domain}[^@\s\."]{1,2000}\.[^\s",]{1,2000}))"{1,20}""",
    """"ClientIP":"(::1|\[?({src_ip}[A-Fa-f:\d.]{1,2000}?)(\]:({src_port}\d{1,100}))?)"""",
    """\ssrc=\[?({src_ip}((\d{1,3}\.){3}\d{1,3}|[A-Fa-f\d]{1,2000}:[a-fA-F\d:]{1,2000}))\]?(:({src_port}\d{1,100}))?\s\w+=""",
    """"result":"({result}[^"]{1,2000})""",
    """"ResultStatus":"({result}[^"]{1,2000}?)"""",
    """\sdestinationServiceName\s{0,100}=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\ssourceServiceName =({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """"User-Agent\\?"{1,20}:\\?"{1,20}({user_agent}[^"\\]{1,2000})"""
    """"UserAgent":"({user_agent}[^"]+)"""",
    """"ipAddress":"({dest_ip}[A-Fa-f.:\d]{1,2000})""""
  
}
```