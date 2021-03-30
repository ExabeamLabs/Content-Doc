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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"signinDateTimeInMillis":\s*({time}\d+)""",
    """"ipAddress":\s*"({src_ip}[A-Fa-f:\d.]+)""",
    """"deviceInformation":\s*"(|({src_host}[\w\-.]+));({os}[^;"]+);(|({browser}[^;"]+));""",
    """"loginStatus":\s*"({outcome}[^"]+)""",
    """"mfaResult":\s*"({additional_info}[^"]+)""",
    """"signinErrorCode":\s*({error_code}\d+)""",
    """"userDisplayName":\s*"({user_firstname}[^,"]+),\s*({user_lastname}[^,"]+)""",
    """"appDisplayName":\s*"({app}[^"]+?)\s*"""",
    """"userPrincipalName":\s*"({user_email}[^\s"@]+@[^\s"@]+)""",
    """"failureReason":\s*"*(null|({failure_reason}[^,"]+))""",
  ]
}
```