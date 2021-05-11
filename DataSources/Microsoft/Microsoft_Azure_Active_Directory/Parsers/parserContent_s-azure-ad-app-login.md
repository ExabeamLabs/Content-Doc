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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"createdDateTime":\s{0,100}"({time}[^"]+)""",
    """"userPrincipalName":\s{0,100}"({user_email}[^"\s@]+@({email_domain}[^"\s@]+))""",
    """"ipAddress":\s{0,100}"({src_ip}[A-Fa-f:\d.]+)""",
    """"browser":\s{0,100}"({browser}[^"]+)""",
    """"operatingSystem":\s{0,100}"({os}[^"]+)""",
    """"userDisplayName":\s{0,100}"({user_lastname}[^,"\(]+?)\s{0,100}(\([^\)]*\))?,\s{0,100}({user_firstname}[^"\(]+?)\s{0,100}(\([^\)]*\))?"""",
    """"failureReason":\s{0,100}"(Other|({failure_reason}[^"]+))""",
    """"errorCode":\s{0,100}({error_code}\d{1,100})""",
    """"appDisplayName":\s{0,100}"({app}[^"]+)""",
    """"location":\s{0,100}\{"({additional_info}.+?)\}
```