#### Parser Content
```Java
{
Name = cef-defender-atp-process
  DataType = "process-created"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceProcessEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [
     """ProcessId":({pid}\d{1,100})""",
     """InitiatingProcessFileName":\s{0,100}"({parent_process}[^"]{1,2000})""",
     """"FileName":\s{0,100}"({process_name}[^"]{1,2000})""",
     """DeviceName":\s{0,100}"({dest_host}[^"]{1,2000})""",
     """ProcessCommandLine":\s{0,100}"({command_line}[^"]{1,2000})\s{0,100}""""
     """MD5":"({md5}[^"]{1,2000})""",
 ]

cef-defender-atp {
     Vendor = Microsoft
     Product = Microsoft Defender ATP
     Lms = Splunk
     TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
     Fields = [
       """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
       """time"{1,20}:\s{0,100}"{1,20}({time}[^"]{1,2000})"""",
       """operationName"{1,20}:\s{0,100}"{1,20}({activity}[^"]{1,2000})""",
       """category"{1,20}:\s{0,100}"{1,20}({category}[^"]{1,2000})""",
       """RemotePort"{1,20}:({dest_port}\d{1,100})""",
       """RemoteIP"{1,20}:\s{0,100}"{1,20}({dest_ip}[^"]{1,2000})""",
       """"Protocol"{1,20}:\s{0,100}"{1,20}({protocol}[^"]{1,2000})""",
       """LocalIP"{1,20}:\s{0,100}"{1,20}({src_ip}[^"]{1,2000})""",
       """LocalPort"{1,20}:({src_port}\d{1,100})""",
       """ActionType"{1,20}:\s{0,100}"{1,20}({outcome}[^"]{1,2000})""",
       """RemoteIPType"{1,20}:\s{0,100}"{1,20}(null|({direction}[^"]{1,2000}))""",
       """DeviceName"{1,20}:\s{0,100}"{1,20}({dest_host}[^"]{1,2000})""",
       """InitiatingProcessAccountName"{1,20}:\s{0,100}"{1,20}((?i)SYSTEM|(?i)network service|({user}[^"]{1,2000}))""",
       """"ProcessIntegrityLevel"{1,20}:\s{0,100}"{1,20}({process_integrity}[^"]{1,2000})""",
       """InitiatingProcessAccountSid"{1,20}:\s{0,100}"{1,20}({user_sid}[^"]{1,2000})""",
       """InitiatingProcessFileName"{1,20}:\s{0,100}"{1,20}({process_name}[^"]{1,2000})""",
     ]
     DupFields = ["category->event_name"
}
```