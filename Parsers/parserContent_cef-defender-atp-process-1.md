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
     """time"+:\s*"+({time}[^"]+)"""",
     """operationName\\?"+:\s*\\?"+({activity}[^"]+?)\\?"""",
     """"category\\?"+:\s*\\?"+({category}[^"]+?)\\?"""",
     """RemoteIP"+:\s*"+({dest_ip}[a-fA-F\d.:]+)""",
     """"Protocol"+:\s*"+({protocol}[^"]+)""",
     """LocalIP"+:\s*"+({src_ip}[a-fA-F\d.:]+)""",
     """LocalPort"+:({src_port}\d+)""",
     """ActionType\\?"+:\s*\\?"+({outcome}[^"]+?)\\?"""",
     """RemoteIPType"+:\s*"+(null|({direction}[^"]+))""",
     """DeviceName\\?"+:\s*\\?"+({dest_host}[^"]+?)\\?"""",
     """InitiatingProcessAccountName\\?"+:\s*\\?"+(system|SYSTEM|({user}[^"]+?))\\?"""",
     """"ProcessIntegrityLevel\\?"+:\s*\\?"+({process_integrity}[^"]+?)\\?"""",
     """InitiatingProcessAccountSid\\?"+:\s*\\?"+({user_sid}[^"]+?)\\?"""",
     """InitiatingProcessFileName\\?"+:\s*\\?"+({process_name}[^"]+?)\\?"""",
     """ProcessId\\?"+:({pid}\d+)""",
     """InitiatingProcessFileName\\?"+:\s*\\?"+({parent_process}[^"]+?)\\?"""",
     """"FileName\\?"+:\s*\\?"+({process_name}[^"]+?)\\?"""",
     """ProcessCommandLine\\?"+:\s*[\\"]*"({command_line}[^"]+?)\\*"""",
     """MD5\\?"+:\\?"+({md5}[^"]+?)\\?"""",
     """\[Namespace:\s*({event_hub_namespace}\S+) ; EventHub name:\s*({event_hub_name}[\w-]+)"""
 ]
 DupFields = ["category->event_name", "event_hub_namespace->host"]
}
```