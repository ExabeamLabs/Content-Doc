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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"createdDateTime"{1,20}:\s{0,100}"{1,20}({time}[^"]+)""",
	"""ms:aad:audit"{1,20}
```