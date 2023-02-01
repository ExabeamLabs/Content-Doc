#### Parser Content
```Java
{
Name = cef-windows-share-access-2
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "share-access"
  TimeFormat = "yyyy-dd-MM'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """CEF:""", """EventSourceName":"Microsoft-Windows-Security-Auditing""", """cat=audit""", """EventID":5143""", """A network share object was modified""" ]
  Fields = [
  """"TimeGenerated":"({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,7}Z)""""
  """"EventID":({event_code}\d{1,100})"""
  """({event_name}A network share object was modified)"""
  """"SubjectLogonId":"({logon_id}[^"]{1,2000})""""
  """"Computer":"({host}[\w\-.]{1,2000})"""
  """"ShareName":"({share_name}[^"]{1,2000})""""
  """"SubjectAccount":"(-|({domain}[\w\-.]{1,100})([\\]{1,100})?({user}[^"]{1,2000}))""""
  """"SubjectUserSid":"({user_sid}[^"]{1,2000})""""
  """"ShareLocalPath":"({share_path}[^"]{1,2000})""""
  ]
  DupFields = [ "host->dest_host" ]
 

}
```