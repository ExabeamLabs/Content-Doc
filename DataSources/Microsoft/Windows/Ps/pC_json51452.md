#### Parser Content
```Java
{
Name = json-5145-2
  DataType = "share-access"
  Conditions = [ """destinationServiceName =Azure""", """"Activity":"5145 - A network share object was checked to see whether the client can be granted desired access."""", """"EventID":5145""", """"EventSourceName":"Microsoft-Windows-Security-Auditing""""]
  Fields = ${WinParserTemplates.json-windows-events-4.Fields}[
    """"ObjectType":"({file_type}[^"]{1,2000})"""",
    """"ShareName":"[\\\*]{0,2000}({share_name}[^"]{1,2000})""",
    """"ShareLocalPath":"(?:[\\\?]{1,2000})?(|({share_path}(({d_parent}.+?)\\\\)?(|({d_name}[^\\]{0,2000}?)))\\?)"""",
    """"RelativeTargetName":"({f_parent}(?:[^"]{1,2000})?[\\\/])?({file_name}[^\\:"]{1,2000}?(\.\s{0,100}({file_ext}[^"\\.]{1,2000}?))?)"""",
    """AccessList"{1,20}:"{1,20}({accesses}[^"]{1,2000}?)(\s(\\t){1,4})?"""",
    """"AccessMask":"({access_mask}[^"]{1,2000})""""
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