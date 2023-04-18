#### Parser Content
```Java
{
Name = json-6273
  Product = Network Policy Server
  DataType = "windows-nac-failed-logon"
  Conditions = [ """"Activity":"6273 - Network Policy Server denied access to a user."""", """"EventID":"6273"""", """"EventSourceName":"Microsoft-Windows-Security-Auditing"""", """"Type":"SecurityEvent"""" ]
  Fields = ${WinParserTemplates.json-windows-events-3.Fields}[
    """({event_name}Network Policy Server denied access to a user)""",
    """"NASIPv(4|6)Address":"({dest_ip}[a-fA-F\d:.]{1,2000})"""",
    """<Data Name\\?="Reason">({failure_reason}[^<]{1,2000})""",
    """"AuthenticationProvider":({auth_server}[^"]{1,2000})"""",
    """"FullyQualifiedSubjectMachineName":"(-|({user_type}[^"]{1,2000}))"""",
    """"SubjectUserName":"((?:host\/)({src_host}[^"]{1,2000})|({user_email}[^@"]{1,2000}@[^"]{1,2000})|(({domain}[^\\"]{1,2000})\\{1,20})?({user}[^"]{1,2000}))"""",
    """NASIdentifier":"(({location}[\w.-]{1,2000}))""""
  ]

json-windows-events-3 = {
  Vendor = Microsoft
  Product = Windows
  Lms = Syslog
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Fields = [
    """"EventID":"({event_code}\d{1,20})"""",
    """"Computer":"({host}[^"]{1,2000})"""",
    """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,9}Z)"""",
    """"SubjectLogonId":"({logon_id}[^"]{1,2000})""",
    """"SubjectUserName":"(-|({user}[^"\/]{1,2000}))"""",
    """"SubjectDomainName":"(-|({domain}[^"]{1,2000}))""",
    """"SubjectUserSid":"({user_sid}[^"]{1,2000})""",
    """"IpAddress":"({src_ip}[a-fA-F\d:.]{1,200})"""",
    """"IpPort":"({src_port}\d{1,5})"""
  
}
```