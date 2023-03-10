#### Parser Content
```Java
{
Name = beyondtrust-app-activity-3
  Vendor = BeyondTrust
  Product = Secure Remote Access
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """act=Add""", """|BeyondTrust|BeyondInsight|""", """fileType=SecretsSafeSecret""", """|AppAudit|Add|""" ]
  Fields = [
  """start=({time}\w{3,4}\s\d{1,2}\s\d{4}\s\d{1,2}:\d{1,2}:\d{1,2})"""
  """src=({src_ip}[A-fa-f\d:.]{1,2000})"""
  """suser=({user}[^\s]{1,2000})"""
  """act=({activity}[^\s]{1,2000})"""
  """dst=({dest_ip}[A-fa-f\d:.]{1,2000})"""
  """\w+\s\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\-.]{1,2000})"""
  """BeyondTrustBeyondInsightEventSeverity=({severity}[^\s]{1,2000})"""
  """({app}BeyondInsight)"""
  """fileType=({additional_info}[^=]{1,2000}?)\s\w+="""
  ]


}
```