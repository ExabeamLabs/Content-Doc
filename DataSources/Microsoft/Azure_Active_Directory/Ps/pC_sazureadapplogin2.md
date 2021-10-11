#### Parser Content
```Java
{
Name = s-azure-ad-app-login-2
  Vendor = Microsoft
  Product = Azure Active Directory
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """authenticationMethod""", """riskLevelDuringSignIn""", """ms:aad:signin""","""tokenIssuerType""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"createdDateTime"{1,20}:\s{0,100}"{1,20}({time}[^"]{1,2000})""",
    """ms:aad:signin"{1,20},"{1,20}({host}[^"]{1,2000})""",
    """"userPrincipalName"{1,20}:\s{0,100}"{1,20}({user_email}[^"\s@]{1,2000}@({email_domain}[^"\s@]{1,2000}))""",
    """"ipAddress"{1,20}:\s{0,100}"{1,20}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"browser"{1,20}:\s{0,100}"{1,20}({browser}[^"]{1,2000})""",
    """"operatingSystem"{1,20}:\s{0,100}"{1,20}({os}[^"]{1,2000})""",
    """"userDisplayName"{1,20}:\s{0,100}"{1,20}({user_fullname}[^"]{1,2000})""",
    """"failureReason"{1,20}:\s{0,100}"{1,20}(Other|({failure_reason}[^"]{1,2000}))""",
    """"errorCode"{1,20}:\s{0,100}({error_code}\d{1,100})""",
    """"appDisplayName"{1,20}:\s{0,100}"{1,20}({app}[^"]{1,2000})""",
    """"location"{1,20}:\s{0,100}\{"{1,20}({additional_info}.+?)\},\s{0,100}"{0,20}servicePrincipalName""",

  ]
}
```