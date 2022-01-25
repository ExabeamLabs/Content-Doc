#### Parser Content
```Java
{
Name = checkpoint-local-logon
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "local-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]: """ , """][""", """ logged in with ReadWrite permission""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\[({src_ip}[A-Fa-f:\d.]{1,2000})\]\[[^\]]{0,2000}\]\[[^\]]{0,2000}\]\[[^\]]{0,2000}\]\s{0,100}<\d{1,100}>(({src_host}[\w\-.]{1,2000})\s{1,100})?({process_name}.+?)\[({pid}\d{1,100})\]:\s{0,100}({additional_info}User\s{1,100}({user}[^\s]{1,2000})\s{1,100}logged in.*?)\s{0,100}$""",
  ]


}
```