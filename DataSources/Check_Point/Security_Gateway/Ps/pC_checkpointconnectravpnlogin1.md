#### Parser Content
```Java
{
Name = checkpoint-connectra-vpn-login-1
  Vendor = Check Point
  Product = Security Gateway
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """cvpn_category:"Session"""", """product:"Connectra"""", """action:"IP Changed"""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """time:"{1,20}({time}\d{1,20})""",
    """assigned_ip:{1,20}"{1,20}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """origin:{1,20}"{1,20}({src_translated_ip}[A-Fa-f:\d.]{1,2000})""",
    """action:"{1,20}({action}[^",;]{1,2000})""",
    """ifdir:"{1,20}({direction}[^",;]{1,2000})""",
    """src:{1,20}"{1,20}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """user:{1,20}"{1,20}CN=(?:[^_]{1,2000}_)?({user}[^",\s=\]]{1,2000})""",
    """om:{1,20}"{1,20}({event_name}[^",;]{1,2000})"""
  ]


}
```