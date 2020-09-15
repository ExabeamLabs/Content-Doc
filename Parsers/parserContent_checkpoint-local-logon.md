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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\[({src_ip}[A-Fa-f:\d.]+)\]\[[^\]]*\]\[[^\]]*\]\[[^\]]*\]\s*<\d+>(({src_host}[\w\-.]+)\s+)?({process_name}.+?)\[({pid}\d+)\]:\s*({additional_info}User\s+({user}[^\s]+)\s+logged in.*?)\s*$""",
  ]
}
```