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
     """time"{1,20}:\s{0,100}"{1,20}({time}[^"]{1,2000})"""",
     """operationName\\?"{1,20}:\s{0,100}\\?"{1,20}({activity}[^"]{1,2000}?)\\?"""",
     """"category\\?"{1,20}:\s{0,100}\\?"{1,20}({category}[^"]{1,2000}?)\\?"""",
     """RemoteIP"{1,20}:\s{0,100}"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
     """"Protocol"{1,20}:\s{0,100}"{1,20}({protocol}[^"]{1,2000})""",
     """LocalIP"{1,20}:\s{0,100}"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
     """LocalPort"{1,20}:({src_port}\d{1,100})""",
     """ActionType\\?"{1,20}:\s{0,100}\\?"{1,20}({outcome}[^"]{1,2000}?)\\?"""",
     """RemoteIPType"{1,20}:\s{0,100}"{1,20}(null|({direction}[^"]{1,2000}))""",
     """DeviceName\\?"{1,20}:\s{0,100}\\?"{1,20}({dest_host}[^"]{1,2000}?)\\?"""",
     """InitiatingProcessAccountName\\?"{1,20}:\s{0,100}\\?"{1,20}(system|SYSTEM|({user}[^"]{1,2000}?))\\?"""",
     """"ProcessIntegrityLevel\\?"{1,20}:\s{0,100}\\?"{1,20}({process_integrity}[^"]{1,2000}?)\\?"""",
     """InitiatingProcessAccountSid\\?"{1,20}:\s{0,100}\\?"{1,20}({user_sid}[^"]{1,2000}?)\\?"""",
     """InitiatingProcessFileName\\?"{1,20}:\s{0,100}\\?"{1,20}({process_name}[^"]{1,2000}?)\\?"""",
     """ProcessId\\?"{1,20}:({pid}\d{1,100})""",
     """InitiatingProcessFileName\\?"{1,20}:\s{0,100}\\?"{1,20}({parent_process}[^"]{1,2000}?)\\?"""",
     """"FileName\\?"{1,20}:\s{0,100}\\?"{1,20}({process_name}[^"]{1,2000}?)\\?"""",
     """ProcessCommandLine\\?"{1,20}:\s{0,100}[\\"]{0,2000}"({command_line}[^"]{1,2000}?)\\*"""",
     """MD5\\?"{1,20}:\\?"{1,20}({md5}[^"]{1,2000}?)\\?"""",
     """\[Namespace:\s{0,100}({event_hub_namespace}\S+) ; EventHub name:\s{0,100}({event_hub_name}[\w-]{1,2000})"""
 ]
 DupFields = ["category->event_name", "event_hub_namespace->host"]
}
```