#### Parser Content
```Java
{
Name = s-lanscope-process-created
  Product = LanScope
  DataType = "process-created"
  IsHVF = true
  Conditions = [ """"リアルタイムイベントログ"""", """"ACTIVE"""" ]
  Fields = ${LanScopeParserTemplates.s-lanscope-app-activity.Fields}[
    ""","*リアルタイムイベントログ"*,"*ACTIVE"*,("*[^"]*"*,){5}"*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d+)\s+\-\s+({account}[^\s@]+)@({dest_host}[^:]+):({command_line}[^"]+)"*,"""
  ]
  DupFields = [ "app->process_name" ]
}
s-lanscope-app-activity = {
  Vendor = LanScope
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    ""","*(|({host}[^"]+))"*,"*(|({user}[^"]+))"*,"*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"*,"*[^"]*"*,"*(|({activity}[^"]+))"*,("*[^"]*"*,){2}"*(|({app}[^"]+))"*,("*[^"]*"*,){2}"*(|({file_path}({file_parent}[^"]+?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?)))"*,"*[^"]*"*,"*(|({bytes_num}\d+)({bytes_unit}\w+))"*,"""
  ]

```