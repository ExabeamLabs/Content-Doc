#### Parser Content
```Java
{
Name = symantec-authentication-successful
  DataType = "authentication-successful"
  Conditions = [ """signed in to the console using Broadcom OKTA authentication flow""","""\"event_id\":20001""" ]
  Fields = ${SymantecParserTemplates.symantec-app-template.Fields}[
    """({event_name}signed in)""",
  ]

symantec-app-template = {
    Vendor = Symantec
    Product = Symantec EDR
    Lms = Syslog
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Fields = [
      """\\"time\\":\\"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """\\"message\\":\\"({additional_info}[^"\\]{1,2000})""",
      """\\"user_name\\":\\"({user}[^\\"]{1,2000})""",
      """\\"event_id\\":({event_code}\d{1,10})""",
      """\\"user_uid\\":\\"({uuid}[^\\"]{1,2000})""",
      """\\"destinationServiceName\\":\\"({app}[^\\"]{1,2000})""",
      """\\"session_uid\\":\\"({session_id}[^\\"]{1,2000})""",
      """\\"ipv4\\":\\"({src_ip}[A-Fa-f\d:.]{1,2000})""",
      """\\"device_os_name\\":\\"({os}[^"\\]{1,2000})""",
      """\\"device_name\\":\\"({host}[\w\-.]{1,2000})""",
      """\\"device_domain\\":\\"({domain}[^"\\]{1,2000})"""
    
}
```