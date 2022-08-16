#### Parser Content
```Java
{
Name = tripwire-file-alert-2
  Vendor = Tripwire Enterprise
  Product = Tripwire Enterprise
  Lms = Splunk
  DataType = "file-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ TE: """, """LogUser=""" , """EventType=""", """ accessed by """  ]

  Fields = [
   """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
   """HostName =({host}[\w.-]{1,2000}?)\s""",
   """LogUser="{0,20}(({domain}[^\\"]{1,2000}?)\\{1,20})?({user}[^\s="]{1,2000}?)"{0,20}\s\w+?=""",
   """EventType=({accesses}[^\s=]{1,2000}?)\s""",
   """AppType="{0,20}({app}[^=]{1,2000}?)"{0,20}\s\w+?=""",
   """NodeIp=({src_ip}[A-Fa-f\d.:]{1,2000}?)\s""",
   """Msg="{1,20}'({file_path}({file_parent}[^'"]{0,2000}?[\\\/]{1,2000})?({file_name}[^'"\\\/]{1,2000}?(\.({file_ext}[^\d]{1,10}?))?))'\saccessed by"""
   ]


}
```