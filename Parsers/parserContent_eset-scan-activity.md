#### Parser Content
```Java
{
Name = eset-scan-activity
  Vendor = ESET
  Product = ESET Endpoint Security
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Scan ID:""" , """End Time:""", """Computer:""", """Domain Name:""", """User1:"""]
  Fields =[
  """({time}\d+-\d+-\d+ \d+:\d+:\d+)""",
  """Scan ID:\s*({scan_id}\d+)""",
  """Computer:\s*({host}[^,]+)""",
  """IP Address:\s*({src_ip}[^,]+)""",
  """Server Name:\s*({dest_host}[^.]+)""",
  """User1:\s*({user}[^,]+)""",
  """Group Name:\s({group}[^,]+)"""
  ]
}
```