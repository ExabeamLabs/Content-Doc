#### Parser Content
```Java
{
Name = cef-defender-atp-process-1
  DataType = "process-created"
  Vendor = Microsoft
  Product = Microsoft Defender ATP
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """CEF""", """SkyFormation Cloud Apps Security""", """AdvancedHunting-DeviceProcessEvents""", """ActionType""", """ProcessCreated""" ]
  Fields = [
     """time"{1,100}:\s{0,100}"{1,100}({time}[^"]+)"""",
     """operationName\\?"{1,100}:\s{0,100}\\?"{1,100}({activity}[^"]+?)\\?"""",
     """"category\\?"{1,100}:\s{0,100}\\?"{1,100}({category}[^"]+?)\\?"""",
     """RemoteIP"{1,100}:\s{0,100}"{1,100}({dest_ip}[a-fA-F\d.:]+)""",
     """"Protocol"{1,100}:\s{0,100}"{1,100}({protocol}[^"]+)""",
     """LocalIP"{1,100}:\s{0,100}"{1,100}({src_ip}[a-fA-F\d.:]+)""",
     """LocalPort"{1,100}:({src_port}\d+)""",
     """ActionType\\?"{1,100}:\s{0,100}\\?"{1,100}({outcome}[^"]+?)\\?"""",
     """RemoteIPType"{1,100}:\s{0,100}"{1,100}(null|({direction}[^"]+))""",
     """DeviceName\\?"{1,100}:\s{0,100}\\?"{1,100}({dest_host}[^"]+?)\\?"""",
     """InitiatingProcessAccountName\\?"{1,100}:\s{0,100}\\?"{1,100}(system|SYSTEM|({user}[^"]+?))\\?"""",
     """"ProcessIntegrityLevel\\?"{1,100}:\s{0,100}\\?"{1,100}({process_integrity}[^"]+?)\\?"""",
     """InitiatingProcessAccountSid\\?"{1,100}:\s{0,100}\\?"{1,100}({user_sid}[^"]+?)\\?"""",
     """InitiatingProcessFileName\\?"{1,100}:\s{0,100}\\?"{1,100}({process_name}[^"]+?)\\?"""",
     """ProcessId\\?"{1,100}:({pid}\d+)""",
     """InitiatingProcessFileName\\?"{1,100}:\s{0,100}\\?"{1,100}({parent_process}[^"]+?)\\?"""",
     """"FileName\\?"{1,100}:\s{0,100}\\?"{1,100}({process_name}[^"]+?)\\?"""",
     """ProcessCommandLine\\?"{1,100}:\s{0,100}[\\"]*"\s{0,100}({command_line}[^"]+?)\s{0,100}\\*"""",
     """MD5\\?"{1,100}:\\?"{1,100}({md5}[^"]+?)\\?"""",
     """\[Namespace:\s{0,100}({event_hub_namespace}\S+) ; EventHub name:\s{0,100}({event_hub_name}[\w-]+)"""
     """"FolderPath"{1,100}:"{1,100}({process}({directory}(\w:)?(?:[^:\]]+)?[\\\/])?({process_name}[^\\\/"\]]+?))"""",    
  ]
  DupFields = ["category->event_name", "event_hub_namespace->host"]
}
```