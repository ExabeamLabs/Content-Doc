#### Parser Content
```Java
{
Name = cef-defender-atp-file
  DataType = "file-operations"
  Conditions = [""""FolderPath"""", """requestClientApplication=""", """AdvancedHunting-DeviceFileEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [
     """"FolderPath"{1,20}:\s{0,100}"{1,20}({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}?(\.({file_ext}\w+))?))"""",
     """DeviceName"{1,20}:\s{0,100}"{1,20}({dest_host}({host}[^"\.]{1,2000})?[^"]{1,2000})""",
     """MD5"{1,20}:"{1,20}({md5}[^"]{1,2000})""",
     """"SHA1"{1,20}:(null|"{1,20}({sha1}[^",]{1,2000})"{1,20}),""",
     """"SHA256"{1,20}:(null|"{1,20}({sha256}[^",]{1,2000})"{1,20}),"""
]

cef-defender-atp {
     Vendor = Microsoft
     Product = Defender ATP
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