#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-40
  Product = Office 365
  Conditions= [ """destinationServiceName =Office 365""", """"Add application""" ]
  Fields = ${MSParserTemplates.cef-microsoft-app-activity.Fields} [
    """"targetResources":[^\}]{1,2000}?"displayName":"({object}[^"]{1,2000})""""
  ]

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
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) [\w\-.]{1,2000} """,
    """"OriginatingServer":"({host}\w+)\s{0,100}(\([^\)]{1,2000}?\))?(\\r\\n)?"""",
    """CEF:([^\|"]{0,2000}\|){5}({activity}[^\|"]{1,2000})""",
    """\sflexString1=({activity}[^=]{1,2000}?)\.?\s{1,100}(\w+=|$)""",
    """"ObjectId":"(Unknown|Not Available|({object}[^"]{1,2000}?))\s{0,100}"""",
    """\sfname=\s{0,100}(N\/A|({object}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """((fileType=(n\/a|N\/A|mail|calendar-event|note|message)[^\n]{0,2000}?\sfname=\s{0,100}(N\/A|({subject}[^=]{1,2000}?)))|(fileType=group[^\n]{0,2000}?\sfname=\s{0,100}(N\/A|({group_name}[^=]{1,2000}?)))|(fileType=(file|folder|attachment|report)[^\n]{0,2000}?\sfname=\s{0,100}(N\/A|({file_name}[^=]{1,2000}?)))|(fileType=process[^\n]{0,2000}?\sfname=\s{0,100}(N\/A|({process_name}[^=]{1,2000}?)))|(fileType=app(lication)?[^\n]{0,2000}?\sfname=\s{0,100}(N\/A|({app}[^=]{1,2000}?))))\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\ssuser=((\w+?_)?(\w+-)?\w+-\w+-\w+-\w+|(Unknown|Microsoft Intune|Microsoft Teams Services|Microsoft Online Services|Office 365 SharePoint Online|anonymous|EMPTY\.*|({user_email}[^@\s"]{1,2000}@[^@\s\."]{1,2000}\.[^\s",]{1,2000})|(({domain}[^\\\s@]{1,2000})\\)?(system|Unknown|({user}[^@\s]{1,2000}))|(Sync Client|Office365 Backend Process|Device Registration Service|({user_fullname}[\w,\s]{1,2000}?))))\s{1,100}(\w+=|$)""",
    """"{1,20}UserId"{1,20}:"{1,20}(({user_email}[^@\s"]{1,2000}?@({email_domain}[^@\s\."]{1,2000}\.[^\s",]{1,2000}))|({user_fullname}({user_firstname}[^"\s]{1,2000})\s({user_lastname}[^"]{1,2000}))|(Unknown|({user}[^"]{1,2000})))"{1,20}""",
    """"ClientIP":"(::1|::ffff:|\[?({src_ip}[A-Fa-f:\d.]{1,2000}?)(\]:({src_port}\d{1,100}))?)"""",
    """\ssrc=\[?(::ffff:)?({src_ip}((\d{1,3}\.){3}\d{1,3}|[A-Fa-f\d]{1,2000}:[a-fA-F\d:]{1,2000}))\]?(:({src_port}\d{1,100}))?\s\w+=""",
    """"result":"({result}[^"]{1,2000})""",
    """"ResultStatus":"({result}[^"]{1,2000}?)"""",
    """\sdestinationServiceName\s{0,100}=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\ssourceServiceName =(Core Directory|Account Provisioning|({app}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
    """"app":\{[^\}]{1,2000}?"displayName":"({app}[^"]{1,2000})"""",
    """"User-Agent\\?"{1,20}:\\?"{1,20}({user_agent}[^"\\]{1,2000})"""
    """"UserAgent":"({user_agent}[^"]+)"""",
    """"ipAddress":"({dest_ip}[A-Fa-f.:\d]{1,2000})"""",
    """"SourceFileName":"({src_file_name}[^",]{1,2000})""",
    """"user":\{[^}]{1,20000}?displayName":"({user_fullname}[^"]{1,2000})"""",
    """"resultReason":"({failure_reason}[^"]{1,2000}?)\s{0,100}""""
  
}
```