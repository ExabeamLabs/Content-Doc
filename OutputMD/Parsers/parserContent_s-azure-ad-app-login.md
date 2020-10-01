#### Parser Content
```Java
{
Name = s-azure-ad-app-login
  Vendor = Microsoft
  Product = Microsoft Azure Active Directory
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """"userDisplayName": """", """"appDisplayName": """", """"createdDateTime": """" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"createdDateTime":\s*"({time}[^"]+)""",
    """"userPrincipalName":\s*"({user_email}[^"\s@]+@({email_domain}[^"\s@]+))""",
    """"ipAddress":\s*"({src_ip}[A-Fa-f:\d.]+)""",
    """"browser":\s*"({browser}[^"]+)""",
    """"operatingSystem":\s*"({os}[^"]+)""",
    """"userDisplayName":\s*"({user_lastname}[^,"\(]+?)\s*(\([^\)]*\))?,\s*({user_firstname}[^"\(]+?)\s*(\([^\)]*\))?"""",
    """"failureReason":\s*"(Other|({failure_reason}[^"]+))""",
    """"errorCode":\s*({error_code}\d+)""",
    """"appDisplayName":\s*"({app}[^"]+)""",
    """"location":\s*\{"({additional_info}.+?)\}
```