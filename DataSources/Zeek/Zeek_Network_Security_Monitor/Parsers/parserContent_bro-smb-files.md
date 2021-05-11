#### Parser Content
```Java
{
Name = bro-smb-files
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"action""", """"smb_files""" ]
  Fields = [
    """exabeam_host=([^@=]+@\s{0,100})?({host}\S+)""",
    """"HOST":\s{0,100}"({host}[^"]+)"""",
    """"TAGS":\s{0,100}"({event_code}[^"]+)"""",
    """"ts":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """SMB::({accesses}\w+)""",
    """"id\.orig_h":"({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p":({src_port}\d{1,100})""",
    """"id\.resp_h":"({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p":({dest_port}\d{1,100})""",
    """"path":"({share_path}[^"]+)""",
    """"name":"({file_path}({file_parent}[^"]*?(\\u005c))?({file_name}[^"\\\/]*?(\.({file_ext}\w+))?))"""",
  ]
}
```