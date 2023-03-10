#### Parser Content
```Java
{
Name = cef-beyondtrust-app-login
  Vendor = BeyondTrust
  Product = BeyondInsight
  Lms = Syslog
  DataType = "app-login"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:0""", """|BeyondTrust|BeyondInsight|""", """|AppAudit|Login|""", """act=Login""", """fileType=""" ]
  Fields = [
  """start=({time}\w{3,4}\s\d{1,2}\s\d{4}\s\d{1,2}:\d{1,2}:\d{1,2})"""
  """src=({src_ip}[A-fa-f\d:.]{1,2000})"""
  """suser=(({domain}[^\\\s]{1,2000})\\{1,100})?({user}[^\s]{1,2000})"""
  """act=({activity}[^\s]{1,2000})"""
  """dst=({dest_ip}[A-fa-f\d:.]{1,2000})"""
  """\w+\s\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\-.]{1,2000})"""
  """BeyondTrustBeyondInsightEventSeverity=({severity}[^\s]{1,2000})"""
  """({app}BeyondInsight)"""
  """BeyondTrustBeyondInsightEventName =({event_name}[^\s]{1,2000}?)\s{0,20}\w+="""
  ]


}
```