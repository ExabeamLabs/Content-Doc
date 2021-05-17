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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"createdDateTime"{1,20}:\s{0,100}"{1,20}({time}[^"]{1,2000})""",
    """ms:aad:audit"{1,20}
```