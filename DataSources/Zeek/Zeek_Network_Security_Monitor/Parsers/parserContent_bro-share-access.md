#### Parser Content
```Java
{
Name = bro-share-access
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"action""", """"SMB::FILE_OPEN"""]
  Fields = [
    """exabeam_host=([^@=]+@\s{0,100})?({host}\S+)""",
    """"HOST"{1,20}:\s{0,100}"{1,20}({host}[^"]+)"""",
    """"TAGS"{1,20}:\s{0,100}"{1,20}({event_code}[^"]+)"""",
    """"ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """SMB::({accesses}FILE_OPEN)""",
    """"id\.orig_h\\?"{1,20}:\\?"({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"{1,20}:({dest_port}[a-fA-F\d.:]+)""",
    """"path\\?"{1,20}:\\?"{1,20}({share_path}[^"]+)""",
    """"name\\?"{1,20}:\\?"{1,20}({file_path}({file_parent}[^"]*?(\\u005c|[\\\/])*)({file_name}[^"\\\/]+?(\.({file_ext}[^"\\\/\.]+))?))\s{0,100}\\?"""",
    """"size\\?"{1,20}:({bytes}\d{1,100})""",
  ]
}
```