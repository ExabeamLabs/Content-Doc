#### Parser Content
```Java
{
Name = s-azure-ad-app-activity-2
  Vendor = Microsoft
  Product = Microsoft Azure Active Directory
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """activityDisplayName""","""ms:aad:audit""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"createdDateTime"+:\s*"+({time}[^"]+)""",
    """ms:aad:audit"+,"+({host}[^"]+)""",
    """"userPrincipalName"+:\s*"+({user_email}[^"\s@]+@[^"\s@]+)""",
    """"ipAddress"+:\s*"+({src_ip}[A-Fa-f:\d.]+)""",
    """"activityDisplayName"+:\s*"+({activity}[^"]+)""",
	""""result"+:\s*"+"({outcome}[^"]+)"""
    ]
}
```