#### Parser Content
```Java
{
Name = json-4622
  DataType = "service-created"
  Conditions = [ """"Activity":"4622 - A security package has been loaded by the Local Security Authority."""", """"EventID":"4622"""", """"EventSourceName":"Microsoft-Windows-Security-Auditing"""", """"Type":"SecurityEvent"""" ]
  Fields = ${WinParserTemplates.json-windows-events-3.Fields}[
    """({event_name}A security package has been loaded by the Local Security Authority)""",
    """ <Data Name\\?="SecurityPackageName">({service_name}[^<]{1,2000})<"""
  ]
  DupFields = ["host->dest_host"]

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