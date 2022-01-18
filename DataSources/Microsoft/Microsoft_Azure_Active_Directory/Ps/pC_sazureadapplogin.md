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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"createdDateTime":\s{0,100}"({time}[^"]{1,2000})""",
    """"userPrincipalName":\s{0,100}"({user_email}[^"\s@]{1,2000}@({email_domain}[^"\s@]{1,2000}))""",
    """"ipAddress":\s{0,100}"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"browser":\s{0,100}"({browser}[^"]{1,2000})""",
    """"operatingSystem":\s{0,100}"({os}[^"]{1,2000})""",
    """"userDisplayName":\s{0,100}"({user_lastname}[^,"\(]{1,2000}?)\s{0,100}(\([^\)]{0,2000}\))?,\s{0,100}({user_firstname}[^"\(]{1,2000}?)\s{0,100}(\([^\)]{0,2000}\))?"""",
    """"failureReason":\s{0,100}"(Other|({failure_reason}[^"]{1,2000}))""",
    """"errorCode":\s{0,100}({error_code}\d{1,100})""",
    """"appDisplayName":\s{0,100}"({app}[^"]{1,2000})""",
    """"location":\s{0,100}\{"({additional_info}.+?)\

}
```