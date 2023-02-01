#### Parser Content
```Java
{
Name = json-5478
  DataType = "service-created"
  Conditions = [ """destinationServiceName =Azure""", """"Activity":"5478""", """IPsec Services has started successfully."""", """"EventID":5478""", """"EventSourceName":"Microsoft-Windows-Security-Auditing""""]
  Fields = ${WinParserTemplates.json-windows-events-4.Fields}[
    """"ManagementGroupName":"({group_name}[^\s"]{1,2000})""",
    """({service_name}IPsec Services)""",
  ]

json-windows-events-4 = {
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Fields = [
    """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,7})?Z)"""",
    """"Computer":"({host}({dest_host}[\w\-\.]{1,2000}))"""",
    """"EventID":({event_code}\d{1,20}),""",
    """"Activity":"\d{1,20}\s\-\s({event_name}[^"]{1,2000})"""",
    """"SubjectUserName":"({user}[^"]{1,2000})"""",
    """"SubjectUserSid":"({user_sid}[^"]{1,2000})"""",
    """"SubjectDomainName":"({domain}[^"]{1,2000})"""",
    """"SubjectLogonId":"({logon_id}[^"]{1,2000})"""",
    """"IpAddress":"({src_ip}[a-fA-F\d:\.]{1,200})"""",
    """"IpPort":"({src_port}\d{1,5})"""
  
}
```