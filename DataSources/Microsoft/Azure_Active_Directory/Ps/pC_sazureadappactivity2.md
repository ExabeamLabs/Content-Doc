#### Parser Content
```Java
{
Name = s-azure-ad-app-activity-2
  Vendor = Microsoft
  Product = Azure Active Directory
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """activityDisplayName""","""ms:aad:audit""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"createdDateTime"{1,20}:\s{0,100}"{1,20}({time}[^"]{1,2000})""",
    """ms:aad:audit"{1,20},"{1,20}({host}[^"]{1,2000})""",
    """"userPrincipalName"{1,20}:\s{0,100}"{1,20}({user_email}[^"\s@]{1,2000}@({email_domain}[^"\s@]{1,2000}))""",
    """"ipAddress"{1,20}:\s{0,100}"{1,20}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"activityDisplayName"{1,20}:\s{0,100}"{1,20}({activity}[^"]{1,2000})""",
	""""result"{1,20}:\s{0,100}"{1,20}"({outcome}[^"]{1,2000})"""
    ]
}
```