#### Parser Content
```Java
{
Name = s-azure-app-login
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch_sec"
  Conditions = [ """"signinDateTimeInMillis":""", """"loginStatus": """", """"mfaAuthDetail":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"signinDateTimeInMillis":\s{0,100}({time}\d{1,100})""",
    """"ipAddress":\s{0,100}"({src_ip}[A-Fa-f:\d.]+)""",
    """"deviceInformation":\s{0,100}"(|({src_host}[\w\-.]+));({os}[^;"]+);(|({browser}[^;"]+));""",
    """"loginStatus":\s{0,100}"({outcome}[^"]+)""",
    """"mfaResult":\s{0,100}"({additional_info}[^"]+)""",
    """"signinErrorCode":\s{0,100}({error_code}\d{1,100})""",
    """"userDisplayName":\s{0,100}"({user_firstname}[^,"]+),\s{0,100}({user_lastname}[^,"]+)""",
    """"appDisplayName":\s{0,100}"({app}[^"]+?)\s{0,100}"""",
    """"userPrincipalName":\s{0,100}"({user_email}[^\s"@]+@({email_domain}[^\s"@]+))""",
    """"failureReason":\s{0,100}"{0,20}(null|({failure_reason}[^,"]+))""",
  ]
}
```