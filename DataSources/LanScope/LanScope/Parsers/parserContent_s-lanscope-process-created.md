#### Parser Content
```Java
{
Name = s-lanscope-process-created
  DataType = "process-created"
  IsHVF = true
  Conditions = [ ""","リアルタイムイベントログ",""", ""","ACTIVE",""" ]
  Fields = ${LanScopeParserTemplates.s-lanscope-app-activity.Fields}[
    ""","リアルタイムイベントログ","ACTIVE",("[^"]*",){5}"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d+)\s+\-\s+({account}[^\s@]+)@({dest_host}[^:]+):({command_line}[^"]+)","""
  ]
  DupFields = [ "app->process_name" ]
}
```