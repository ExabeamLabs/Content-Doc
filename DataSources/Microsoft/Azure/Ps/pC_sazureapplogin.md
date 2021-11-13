#### Parser Content
```Java
{
Name = s-azure-app-login
  Vendor = Microsoft
  Product = Azure
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch_sec"
  Conditions = [ """"signinDateTimeInMillis":""", """"loginStatus": """", """"mfaAuthDetail":""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"signinDateTimeInMillis":\s{0,100}({time}\d{1,100})""",
    """"ipAddress":\s{0,100}"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"loginStatus":\s{0,100}"({outcome}[^"]{1,2000})""",
    """"mfaResult":\s{0,100}"({additional_info}[^"]{1,2000})""",
    """"signinErrorCode":\s{0,100}({error_code}\d{1,100})""",
    """"userDisplayName":\s{0,100}"({user_firstname}[^,"]{1,2000}),\s{0,100}({user_lastname}[^,"]{1,2000})""",
    """"appDisplayName":\s{0,100}"({app}[^"]{1,2000}?)\s{0,100}"""",
    """"userPrincipalName":\s{0,100}"({user_email}[^\s"@]{1,2000}@({email_domain}[^\s"@]{1,2000}))""",
    """"failureReason":\s{0,100}"{0,20}(null|({failure_reason}[^,"]{1,2000}))""",
  ]


}
```