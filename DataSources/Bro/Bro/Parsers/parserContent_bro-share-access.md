#### Parser Content
```Java
{
Name = bro-share-access
  Vendor = Bro
  Product = Bro
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"action""", """"SMB::FILE_OPEN"""]
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
    """"HOST"+:\s*"+({host}[^"]+)"""",
    """"TAGS"+:\s*"+({event_code}[^"]+)"""",
    """"ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """SMB::({accesses}FILE_OPEN)""",
    """"id\.orig_h\\?"+:\\?"({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}[a-fA-F\d.:]+)""",
    """"path\\?"+:\\?"+({share_path}[^"]+)""",
    """"name\\?"+:\\?"+({file_path}({file_parent}[^"]*?(\\u005c|[\\\/])*)({file_name}[^"\\\/]+?(\.({file_ext}[^"\\\/\.]+))?))\s*\\?"""",
    """"size\\?"+:({bytes}\d+)""",
  ]
}
```