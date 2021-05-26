#### Parser Content
```Java
{
Name = s-azure-ad-app-login-2
  Vendor = Microsoft
  Product = Microsoft Azure Active Directory
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """authenticationMethod""", """riskLevelDuringSignIn""", """ms:aad:signin""","""tokenIssuerType""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"createdDateTime"{1,20}:\s{0,100}"{1,20}({time}[^"]{1,2000})""",
    """ms:aad:signin"{1,20}
```