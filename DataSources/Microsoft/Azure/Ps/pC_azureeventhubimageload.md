#### Parser Content
```Java
{
Name = azure-event-hub-image-load
    Vendor = Microsoft
    Product = Azure
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    DataType = "image-loaded"
    Conditions = ["""|beatname=eventhubbeat|""", """|device_type=eventhubbeat|""", """|subject=AdvancedHunting-DeviceImageLoadEvents|""", """vmid=""", """@timestamp""", """@metadata"""]
    Fields = [
      """time"{1,20}:\s{0,100}"{1,20}({time}[^"]{1,2000})"""",  
      """category":"({category}[^"]{1,2000})""",
      """ActionType":"({event_name}[^"]{1,2000})""",
      """"DeviceName"{1,20}:\s{0,100}"{1,20}({dest_host}({host}[^"\.]{1,2000})?[^"]{1,2000})""",
      """"FileName":"{1,20}({file_name}[^"]{1,2000}?(\.({file_ext}\w+))?)"""",
      """"FolderPath":"{1,20}({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}?(\.({file_ext}\w+))?))"""", 
      """"InitiatingProcessAccountDomain":"({domain}[^"]{1,2000})""",
      """"InitiatingProcessAccountName":"(system|local service|SYSTEM|NETWORK SERVICE|({user}[^"]{1,2000}))""",
      """"InitiatingProcessAccountSid":"({user_sid}[^"]{1,2000})""",
      """"InitiatingProcessCommandLine":"\s{0,100}({command_line}.+?)\s{0,100}"\,""",
      """"InitiatingProcessFileName":"({process_name}[^"]{1,2000})""",
      """"InitiatingProcessFolderPath":"{1,20}({process}({process_directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}?\.\w+?))"""",
      """"MD5":"({md5}[^"]{1,2000})""",
      """"InitiatingProcessId":({pid}\d{1,100})""",
      """"InitiatingProcessLogonId":({logon_id}\d{1,100})""",
    ]
    DupFields = ["process_directory->directory"]



}
```