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
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"HOST"{1,20}:\s{0,100}"{1,20}({host}[^"]{1,2000})"""",
    """"TAGS"{1,20}:\s{0,100}"{1,20}({event_code}[^"]{1,2000})"""",
    """"ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """SMB::({accesses}FILE_OPEN)""",
    """"id\.orig_h\\?"{1,20}:\\?"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p\\?"{1,20}:({dest_port}[a-fA-F\d.:]{1,2000})""",
    """"path\\?"{1,20}:\\?"{1,20}({share_path}[^"]{1,2000})""",
    """"name\\?"{1,20}:\\?"{1,20}({file_path}({file_parent}[^"]{0,2000}?(\\u005c|[\\\/])*)({file_name}[^"\\\/]{1,2000}?(\.({file_ext}[^"\\\/\.]{1,2000}))?))\s{0,100}\\?"""",
    """"size\\?"{1,20}:({bytes}\d{1,100})""",
  ]
}
```