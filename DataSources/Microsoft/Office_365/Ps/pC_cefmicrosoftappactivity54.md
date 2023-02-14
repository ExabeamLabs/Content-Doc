#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-54
  Product = Office 365
  Conditions= [ """destinationServiceName =Office 365""", """"Operation":"SoftDelete"""", """"UserId":"""" ]

cef-microsoft-o365-app-activity = {
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """"CreationTime\\*"{1,20}:[\s\\]{0,2000}"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"OriginatingServer":"({dest_host}({host}\w+))\s{0,100}(\([^\)]{1,2000}?\))?(\\r\\n)?"""",
    """CEF:([^\|"]{0,2000}\|){5}({activity}[^\|"]{1,2000})""",
    """\sflexString1=({event_name}[^=]{1,2000}?)\.?\s{1,100}(\w+=|$)""",
    """"Operation":"({activity}[^"]{1,2000}?)\.?"""",
    """\sfname=\s{0,100}(N\/A|({object}[^=\s]{1,2000}))""",
    """((fileType=(n\/a|N\/A|mail|calendar-event|note|message)[^\n]{0,2000}?\sfname=\s{0,100}(N\/A|({subject}[^=]{1,2000}?)))|(fileType=group[^\n]{0,2000}?\sfname=\s{0,100}(N\/A|({group_name}[^=]{1,2000}?)))|(fileType=(file|folder|attachment|report)[^\n]{0,2000}?\sfname=\s{0,100}(N\/A|({file_name}[^=]{1,2000}?)))|(fileType=process[^\n]{0,2000}?\sfname=\s{0,100}(N\/A|({process_name}[^=]{1,2000}?)))|(fileType=app(lication)?[^\n]{0,2000}?\sfname=\s{0,100}(N\/A|({app}[^=]{1,2000}?))))\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\ssuser=((\w+?_)?(\w+-)?\w+-\w+-\w+-\w+|(Unknown|Microsoft Intune|Microsoft Teams (Templates )?Service(s)?|Microsoft Online Services|Office 365 (SharePoint|Exchange) Online|anonymous|EMPTY\.*|(\w{1,5}:\w{1,5}:[^\#]{1,20}\#)?({user_email}[^@\s"]{1,2000}@[^@\s\."]{1,2000}\.[^\s",]{1,2000})|(({domain}[^\\\s@]{1,2000})\\)?(system|Unknown|Signup|({user}[^@\s]{1,2000}))|(Sync Client|Office365 Backend Process|Device Registration Service|Managed Service Identity|Microsoft Substrate Management|Microsoft Approval Management|Office 365 Exchange Online|Office 365 SharePoint Online|Microsoft Office 365 Portal|Microsoft App Access Panel|Microsoft Invitation Acceptance Portal|Azure ESTS Service|Microsoft B2B Admin Worker|Microsoft Stream Portal|Microsoft Stream Service|Azure AD Cloud Sync|Azure AD PIM|Portfolios|ProjectWorkManagement|AAD Terms Of Use|({user_fullname}[\w,\s]{1,2000}?))))\s{1,100}(\w+=|$)""",
    """"{1,20}UserId"{1,20}:"{1,20}((\w{1,5}:\w{1,5}:[^\#]{1,20}\#)?({user_email}[^@\s"]{1,2000}?@({email_domain}[^@\s\."]{1,2000}\.[^\s",]{1,2000}))|({user_fullname}({user_firstname}[^"\s]{1,2000})\s({user_lastname}[^"]{1,2000}))|(Unknown|({user_sid}[^"]{1,2000})))"{1,20}""",
    """"ClientIP":"(::1|::ffff:|\[?(::ffff:)?({src_ip}[A-Fa-f:\d.]{1,2000}?)(\]:({src_port}\d{1,100}))?)"""",
    """\ssrc=\[?(::ffff:)?({src_ip}((\d{1,3}\.){3}\d{1,3}|[A-Fa-f\d]{1,2000}:[a-fA-F\d:]{1,2000}))\]?(:({src_port}\d{1,100}))?\s\w+=""",
    """"ResultStatus":"({result}[^"]{1,2000}?)"""",
    """\sdestinationServiceName\s{0,100}=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\ssourceServiceName =(Core Directory|Account Provisioning|({app}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
    """\WfilePath=(((?i)N\/A)|([A-Za-z\d]{1,2000})|({file_path}[^=]+?))\s{0,100}(\w+=|$)""",
    """\WfilePath=(((?i)N\/A)|(({file_parent}[^=]+?)\/({file_name}[^\/=]{1,2000}?)))\s{0,100}(\w+=|$)""",
    """\WfilePath=[^=]*?(\.({file_ext}[^\/\.]{0,2000}?))?\s{0,100}(\w+=|$)""",
    """"ClientProcessName":"({process_name}[^"]{1,2000})"""
  
}
```