#### Parser Content
```Java
{
Name = s-azure-ad-password-change-2
  Vendor = Microsoft
  Product = Microsoft Azure Active Directory
  Lms = Splunk
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """activityDisplayName""","""ms:aad:audit""","""Self-service password reset flow activity progress""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"createdDateTime"+:\s*"+({time}[^"]+)""",
	"""ms:aad:audit"+,"+({host}[^"]+)""",
    """"userPrincipalName"+:\s*"+({user_email}[^"\s@]+@({email_domain}[^"\s@]+))""",
    """"ipAddress"+:\s*"+({src_ip}[A-Fa-f:\d.]+)""",
    """"activityDisplayName"+:\s*"+({activity}[^"]+)""",
	""""result"+:\s*"+"({outcome}[^"]+)"""
    ]
}
```